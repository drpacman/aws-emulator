// SPDX-License-Identifier: CC0-1.0

//! The Elastic Load Balancing v2 resources a stack declares are CREATED in Elastic Load
//! Balancing, and removed from it again with the stack.
//!
//! The rule under test: **an `AWS::ElasticLoadBalancingV2::LoadBalancer`, `::TargetGroup` and
//! `::Listener` a stack reports created are resources Elastic Load Balancing holds, under the
//! ARN the stack publishes** — so a client that deploys the stack and then calls
//! `elbv2 describe-load-balancers` with that ARN reads the load balancer back, an attribute
//! only that service reports (`CanonicalHostedZoneID`, which a Route 53 alias needs) resolves
//! to the value it reports, and a declaration that service refuses fails the stack rather
//! than deploying as though it could work.
//!
//! Every case drives the real request path through the router `stack_lifecycle.rs` builds —
//! CloudFormation over its awsQuery wire, the reads over Elastic Load Balancing's own.

use std::time::Duration;

use smithy_server_runtime::MultiServiceRouter;

use crate::stack_lifecycle::{
    call, create_stack, describe_stack, form_encode, member, resource_event_reason, router,
    xml_text, REGION,
};
use crate::stack_outputs::{output_for, wire_outputs};
use service_com_amazonaws_cloudformation_cloudformation::state::status;

/// The Route 53 hosted zone Elastic Load Balancing publishes for an application load
/// balancer in `us-east-1` ("Elastic Load Balancing endpoints and quotas").
const US_EAST_1_ALB_HOSTED_ZONE: &str = "Z35SXDOTRQ7X7K";

/// How long a case waits for a stack to reach a terminal status: the load balancer is
/// answered `provisioning` and the stack holds its creation open until it is `active`.
const SETTLE_WITHIN: Duration = Duration::from_secs(15);

/// One awsQuery call to Elastic Load Balancing v2 over the same router, answered with the
/// HTTP status and the XML body, signed for `elasticloadbalancing` under that service's own
/// API version (`version: 2015-12-01`).
async fn elbv2(
    router: &MultiServiceRouter,
    action: &str,
    params: &[(&str, &str)],
) -> (u16, String) {
    let mut body = format!("Action={action}&Version=2015-12-01");
    for (name, value) in params {
        body.push('&');
        body.push_str(&form_encode(name));
        body.push('=');
        body.push_str(&form_encode(value));
    }
    let request = http::Request::builder()
        .method("POST")
        .uri("/")
        .header(
            "host",
            format!("elasticloadbalancing.{REGION}.amazonaws.com"),
        )
        .header("content-type", "application/x-www-form-urlencoded")
        .header(
            "authorization",
            format!(
                "AWS4-HMAC-SHA256 \
                 Credential=AKIDEXAMPLE/20260101/{REGION}/elasticloadbalancing/aws4_request, \
                 SignedHeaders=host, Signature=0123456789abcdef"
            ),
        )
        .body(bytes::Bytes::from(body))
        .expect("a well-formed Elastic Load Balancing request");
    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let body = String::from_utf8_lossy(response.body()).to_string();
    (status, body)
}

/// Read the stack until it reports a status no further wait changes, answering the last
/// `DescribeStacks` body — or `None` for a stack that no longer exists.
async fn settled(router: &MultiServiceRouter, stack: &str) -> Option<String> {
    let deadline = tokio::time::Instant::now() + SETTLE_WITHIN;
    loop {
        let (status_code, body) = describe_stack(router, stack).await;
        if status_code != 200 {
            return None;
        }
        let reported = xml_text(&body, "StackStatus").unwrap_or_default();
        if !reported.ends_with("_IN_PROGRESS") || tokio::time::Instant::now() >= deadline {
            return Some(body);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The value the stack reports for output `key`, or the empty string.
fn output(body: &str, key: &str) -> String {
    output_for(&wire_outputs(body), key)
        .and_then(|output| output.value.clone())
        .unwrap_or_default()
}

/// A VPC and two subnets in different zones, created in Amazon EC2 by the same stack:
/// Elastic Load Balancing places an application load balancer only in subnets EC2 holds, in
/// at least two Availability Zones.
const NETWORK: &str = "  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.0.1.0/24
      AvailabilityZone: us-east-1a
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.0.2.0/24
      AvailabilityZone: us-east-1b
";

/// The shape a web tier's stack declares: a load balancer, a target group with a registered
/// target, a listener forwarding to it, and a resource that READS the load balancer's
/// hosted zone — standing in for the `AWS::Route53::RecordSet` alias that needs it — so the
/// stack completes only if that value resolved.
fn web_tier_template() -> String {
    format!(
        "Resources:\n{NETWORK}  Alb:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Name: web-alb
      Subnets: [!Ref SubnetA, !Ref SubnetB]
      Tags:
        - Key: team
          Value: web
  Tg:
    Type: AWS::ElasticLoadBalancingV2::TargetGroup
    Properties:
      Port: 3000
      Protocol: HTTP
      VpcId: !Ref Vpc
      TargetType: ip
      HealthCheckPath: /health
      Targets:
        - Id: 10.0.1.25
          Port: 3000
  Listener:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      LoadBalancerArn: !Ref Alb
      Port: 80
      Protocol: HTTP
      DefaultActions:
        - Type: forward
          TargetGroupArn: !Ref Tg
  ZoneRecord:
    Type: AWS::SSM::Parameter
    Properties:
      Type: String
      Value: !GetAtt Alb.CanonicalHostedZoneID
Outputs:
  AlbArn:
    Value: !Ref Alb
  AlbDns:
    Value: !GetAtt Alb.DNSName
  AlbZone:
    Value: !GetAtt Alb.CanonicalHostedZoneID
  AlbFullName:
    Value: !GetAtt Alb.LoadBalancerFullName
  TgArn:
    Value: !Ref Tg
  ListenerArn:
    Value: !Ref Listener
"
    )
}

#[tokio::test]
async fn a_declared_load_balancer_target_group_and_listener_exist_in_elastic_load_balancing() {
    let router = router();
    let case = "a load balancer, a target group with a target, and a listener";
    let (status_code, body) = create_stack(&router, "web-tier", &web_tier_template(), &[]).await;
    assert_eq!(
        status_code, 200,
        "case {case:?}: CreateStack answered {status_code}: {body}"
    );
    let body = settled(&router, "web-tier")
        .await
        .expect("the stack exists");
    assert_eq!(
        xml_text(&body, "StackStatus").as_deref(),
        Some(status::CREATE_COMPLETE),
        "case {case:?}: expected the stack to complete, got reason {:?}",
        xml_text(&body, "StackStatusReason")
    );

    let alb_arn = output(&body, "AlbArn");
    let tg_arn = output(&body, "TgArn");
    let listener_arn = output(&body, "ListenerArn");

    // The attribute only Elastic Load Balancing reports resolves to what it reports.
    assert_eq!(
        output(&body, "AlbZone"),
        US_EAST_1_ALB_HOSTED_ZONE,
        "case {case:?}: expected CanonicalHostedZoneID to be the Region's published zone"
    );

    // The load balancer is there, under the ARN the stack published, with the DNS name the
    // stack reported, and active.
    let (status_code, described) = elbv2(
        &router,
        "DescribeLoadBalancers",
        &[("LoadBalancerArns.member.1", &alb_arn)],
    )
    .await;
    assert_eq!(
        status_code, 200,
        "case {case:?}: DescribeLoadBalancers({alb_arn}) answered {described}"
    );
    assert_eq!(
        xml_text(&described, "DNSName"),
        Some(output(&body, "AlbDns")),
        "case {case:?}: the DNS name the stack reports is the one the service holds"
    );
    assert_eq!(
        xml_text(&described, "Code").as_deref(),
        Some("active"),
        "case {case:?}: {described}"
    );
    assert!(
        alb_arn.ends_with(&format!("loadbalancer/{}", output(&body, "AlbFullName"))),
        "case {case:?}: LoadBalancerFullName is the ARN's resource path, got {alb_arn} and {}",
        output(&body, "AlbFullName")
    );

    // It carries the declared tag and the ones CloudFormation records on every resource.
    let (_, tags) = elbv2(
        &router,
        "DescribeTags",
        &[("ResourceArns.member.1", &alb_arn)],
    )
    .await;
    for key in [
        "team",
        "aws:cloudformation:stack-name",
        "aws:cloudformation:logical-id",
    ] {
        assert!(
            tags.contains(&format!("<Key>{key}</Key>")),
            "case {case:?}: expected tag {key:?} in {tags}"
        );
    }

    // The target group is there, configured as declared, with its declared target registered.
    let (status_code, group) = elbv2(
        &router,
        "DescribeTargetGroups",
        &[("TargetGroupArns.member.1", &tg_arn)],
    )
    .await;
    assert_eq!(
        status_code, 200,
        "case {case:?}: DescribeTargetGroups({tg_arn}) answered {group}"
    );
    assert_eq!(
        xml_text(&group, "HealthCheckPath").as_deref(),
        Some("/health"),
        "case {case:?}: {group}"
    );
    let (status_code, health) = elbv2(
        &router,
        "DescribeTargetHealth",
        &[("TargetGroupArn", &tg_arn)],
    )
    .await;
    assert_eq!(
        status_code, 200,
        "case {case:?}: DescribeTargetHealth answered {health}"
    );
    assert!(
        health.contains("<Id>10.0.1.25</Id>"),
        "case {case:?}: expected the target registered, got {health}"
    );

    // The listener is there, on that load balancer, forwarding to that target group.
    let (status_code, listener) = elbv2(
        &router,
        "DescribeListeners",
        &[("ListenerArns.member.1", &listener_arn)],
    )
    .await;
    assert_eq!(
        status_code, 200,
        "case {case:?}: DescribeListeners({listener_arn}) answered {listener}"
    );
    assert_eq!(
        xml_text(&listener, "LoadBalancerArn"),
        Some(alb_arn.clone()),
        "case {case:?}"
    );
    assert_eq!(
        xml_text(&listener, "TargetGroupArn"),
        Some(tg_arn.clone()),
        "case {case:?}"
    );
}

#[tokio::test]
async fn deleting_the_stack_removes_its_resources_from_elastic_load_balancing() {
    let router = router();
    let case = "delete a web tier stack";
    let (status_code, body) = create_stack(&router, "web-gone", &web_tier_template(), &[]).await;
    assert_eq!(
        status_code, 200,
        "case {case:?}: CreateStack answered {status_code}: {body}"
    );
    let body = settled(&router, "web-gone")
        .await
        .expect("the stack exists");
    assert_eq!(
        xml_text(&body, "StackStatus").as_deref(),
        Some(status::CREATE_COMPLETE),
        "case {case:?}: {body}"
    );
    let alb_arn = output(&body, "AlbArn");
    let tg_arn = output(&body, "TgArn");
    let listener_arn = output(&body, "ListenerArn");

    let (status_code, body) =
        call(&router, "DeleteStack", &[member("StackName", "web-gone")]).await;
    assert_eq!(
        status_code, 200,
        "case {case:?}: DeleteStack answered {body}"
    );
    let _ = settled(&router, "web-gone").await;

    for (action, member_name, arn, not_found) in [
        (
            "DescribeLoadBalancers",
            "LoadBalancerArns.member.1",
            &alb_arn,
            "LoadBalancerNotFound",
        ),
        (
            "DescribeTargetGroups",
            "TargetGroupArns.member.1",
            &tg_arn,
            "TargetGroupNotFound",
        ),
        (
            "DescribeListeners",
            "ListenerArns.member.1",
            &listener_arn,
            "ListenerNotFound",
        ),
    ] {
        let (status_code, answered) = elbv2(&router, action, &[(member_name, arn)]).await;
        assert!(
            status_code == 400 && answered.contains(not_found),
            "case {case:?}: expected {action}({arn}) to answer {not_found} once the stack is \
             deleted, got {status_code} {answered}"
        );
    }
}

#[tokio::test]
async fn a_listener_elastic_load_balancing_refuses_fails_the_stack_and_leaves_nothing_behind() {
    let router = router();
    let case = "a listener declaring no default action";
    let template = format!(
        "Resources:\n{NETWORK}  Alb:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Name: refused-alb
      Subnets: [!Ref SubnetA, !Ref SubnetB]
  Listener:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      LoadBalancerArn: !Ref Alb
      Port: 80
      Protocol: HTTP
"
    );
    let (status_code, body) = create_stack(&router, "refused-listener", &template, &[]).await;
    assert_eq!(
        status_code, 200,
        "case {case:?}: CreateStack answered {status_code}: {body}"
    );
    let body = settled(&router, "refused-listener")
        .await
        .expect("the stack exists");
    assert_eq!(
        xml_text(&body, "StackStatus").as_deref(),
        Some(status::ROLLBACK_COMPLETE),
        "case {case:?}: expected the stack to roll back, got {body}"
    );
    let reason =
        resource_event_reason(&router, "refused-listener", "Listener", "CREATE_FAILED").await;
    assert!(
        !reason.is_empty(),
        "case {case:?}: expected the listener's failure to carry Elastic Load Balancing's refusal"
    );
    // The rollback took the load balancer the stack had created away again.
    let (status_code, answered) = elbv2(
        &router,
        "DescribeLoadBalancers",
        &[("Names.member.1", "refused-alb")],
    )
    .await;
    assert!(
        status_code == 400 && answered.contains("LoadBalancerNotFound"),
        "case {case:?}: expected no load balancer left behind, got {status_code} {answered}"
    );
}

/// The same web tier deployed the way `aws cloudformation deploy` does it — a `CREATE` change
/// set, executed — completes just as `CreateStack` does: the listener and the resource
/// reading the load balancer's hosted zone are withheld while the load balancer is
/// `provisioning`, and created once it is `active`.
#[tokio::test]
async fn a_web_tier_deployed_through_a_change_set_completes() {
    use crate::change_set_lifecycle::{
        create_creating_change_set, describe_change_set, execute_change_set,
    };
    let router = router();
    let case = "a web tier deployed through an executed CREATE change set";
    let (status_code, body) =
        create_creating_change_set(&router, "web-cs", "web-cs-1", &web_tier_template()).await;
    assert_eq!(status_code, 200, "case {case:?}: CreateChangeSet answered {body}");
    let deadline = tokio::time::Instant::now() + SETTLE_WITHIN;
    loop {
        let (_, described) = describe_change_set(&router, "web-cs-1", Some("web-cs")).await;
        let reported = xml_text(&described, "Status").unwrap_or_default();
        if reported == "CREATE_COMPLETE" {
            break;
        }
        assert!(
            !reported.ends_with("FAILED") && tokio::time::Instant::now() < deadline,
            "case {case:?}: the change set did not become executable: {described}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (status_code, body) = execute_change_set(&router, "web-cs-1", Some("web-cs")).await;
    assert_eq!(status_code, 200, "case {case:?}: ExecuteChangeSet answered {body}");
    let body = settled(&router, "web-cs").await.expect("the stack exists");
    if xml_text(&body, "StackStatus").as_deref() != Some(status::CREATE_COMPLETE) {
        let (_, events) = call(&router, "DescribeStackEvents", &[member("StackName", "web-cs")]).await;
        let lines: Vec<String> = events
            .split("<member>")
            .skip(1)
            .map(|event| {
                format!(
                    "{:?} {:?} {:?}",
                    xml_text(event, "LogicalResourceId"),
                    xml_text(event, "ResourceStatus"),
                    xml_text(event, "ResourceStatusReason")
                )
            })
            .collect();
        panic!("case {case:?}: expected CREATE_COMPLETE, got {body}\nevents:\n{}", lines.join("\n"));
    }
    assert_eq!(output(&body, "AlbZone"), US_EAST_1_ALB_HOSTED_ZONE, "case {case:?}");
}

/// A stack nobody reads until long after its load balancer came up still completes: the
/// resources withheld behind the load balancer were released when Elastic Load Balancing
/// reported it `active`, not when a client next happened to poll — and a client that polls
/// rarely (`aws cloudformation deploy` waits 30 seconds between reads) must not see them
/// failed as having waited too long.
#[tokio::test]
async fn resources_withheld_behind_the_load_balancer_survive_a_late_first_read() {
    use crate::stack_lifecycle::{router_with_engine, store};
    use service_com_amazonaws_cloudformation_cloudformation::state::stabilising::CREATE_STABILISATION_WINDOW;

    let (router, engine) = router_with_engine();
    let case = "the first read comes after every wait's window has run out";
    let (status_code, body) = create_stack(&router, "late-read", &web_tier_template(), &[]).await;
    assert_eq!(status_code, 200, "case {case:?}: CreateStack answered {status_code}: {body}");
    // Let the load balancer reach `active` in Elastic Load Balancing, with no read of the
    // stack in between…
    tokio::time::sleep(Duration::from_millis(800)).await;
    // …then make the first read land after every wait's window, as a slow poller's does, by
    // moving the instant each wait began into the past rather than sleeping it out.
    {
        let state = store(&engine);
        let mut held = state.lock();
        let past = CREATE_STABILISATION_WINDOW + Duration::from_secs(1);
        for stack in &mut held.stacks {
            for barrier in &mut stack.stabilisations {
                barrier.asked_at -= past;
                barrier.opened_at -= past;
            }
        }
    }
    let body = settled(&router, "late-read").await.expect("the stack exists");
    assert_eq!(
        xml_text(&body, "StackStatus").as_deref(),
        Some(status::CREATE_COMPLETE),
        "case {case:?}: expected the stack to complete, got reason {:?}",
        xml_text(&body, "StackStatusReason")
    );
    assert_eq!(output(&body, "AlbZone"), US_EAST_1_ALB_HOSTED_ZONE, "case {case:?}");
}

/// A resource reading another's attribute is created with the value that resource's OWNING
/// SERVICE reported, even where the resource it reads was ready the moment its create
/// answered — so nothing was withheld — and the value is composed into a longer string, where
/// no stand-in CloudFormation computed before deployment could be swapped for it whole.
///
/// The target group is ready as `CreateTargetGroup` answers, and its `TargetGroupFullName`
/// carries the id Elastic Load Balancing assigned; the parameter's `Value` embeds it. What
/// Systems Manager holds is read back over its own wire.
#[tokio::test]
async fn a_composed_attribute_of_a_resource_ready_at_once_reaches_its_consumer() {
    use crate::dynamic_references::ssm;
    let router = router();
    let case = "Fn::Sub embedding a target group's full name";
    let template = format!(
        "Resources:\n{NETWORK}  Tg:
    Type: AWS::ElasticLoadBalancingV2::TargetGroup
    Properties:
      Port: 80
      Protocol: HTTP
      VpcId: !Ref Vpc
  Param:
    Type: AWS::SSM::Parameter
    Properties:
      Name: /composed/target-group
      Type: String
      Value: !Sub \"tg=${{Tg.TargetGroupFullName}}\"
Outputs:
  TgFullName:
    Value: !GetAtt Tg.TargetGroupFullName
"
    );
    let (status_code, body) = create_stack(&router, "composed", &template, &[]).await;
    assert_eq!(status_code, 200, "case {case:?}: CreateStack answered {status_code}: {body}");
    let body = settled(&router, "composed").await.expect("the stack exists");
    assert_eq!(
        xml_text(&body, "StackStatus").as_deref(),
        Some(status::CREATE_COMPLETE),
        "case {case:?}: reason {:?}",
        xml_text(&body, "StackStatusReason")
    );
    let full_name = output(&body, "TgFullName");
    let (status_code, parameter) = ssm(
        &router,
        "GetParameter",
        &serde_json::json!({"Name": "/composed/target-group"}),
    )
    .await;
    assert_eq!(status_code, 200, "case {case:?}: GetParameter answered {parameter}");
    assert_eq!(
        parameter["Parameter"]["Value"].as_str(),
        Some(format!("tg={full_name}").as_str()),
        "case {case:?}: expected the parameter to embed the full name Elastic Load Balancing \
         assigned"
    );
}
