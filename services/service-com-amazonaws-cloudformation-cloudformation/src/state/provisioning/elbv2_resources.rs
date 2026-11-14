// SPDX-License-Identifier: CC0-1.0

//! The Elastic Load Balancing v2 load balancer, target group, listener and listener rule a
//! stack declares, CREATED in Elastic Load Balancing itself.
//!
//! ## The rule this module carries
//!
//! A declared resource of a type whose owning service this emulator serves is created by that
//! service's own create call, so the call's REFUSAL is the resource's failure and the
//! identifier the call answers with is what the stack publishes. Before this module the three
//! `AWS::ElasticLoadBalancingV2::*` types were DECLARED-ONLY: a stack reported them created
//! under an ARN nothing in Elastic Load Balancing answered to, `describe-load-balancers`
//! listed nothing, and an attribute only that service reports — the load balancer's
//! `CanonicalHostedZoneID`, which an `AWS::Route53::RecordSet` alias needs — resolved to no
//! value at all.
//!
//! * `AWS::ElasticLoadBalancingV2::LoadBalancer` is created by `CreateLoadBalancer`;
//! * `AWS::ElasticLoadBalancingV2::TargetGroup` by `CreateTargetGroup`, with its declared
//!   `Targets` registered by `RegisterTargets`;
//! * `AWS::ElasticLoadBalancingV2::Listener` by `CreateListener`;
//! * `AWS::ElasticLoadBalancingV2::ListenerRule` by `CreateRule`. A rule's ARN nests inside
//!   its listener's, so once the listener's ARN is the one Elastic Load Balancing minted, a
//!   rule left declared-only would publish an ARN nested in a listener that exists nowhere.
//!
//! Each type's declared `…Attributes` list is written by that type's own
//! `Modify…Attributes` call once the resource exists, since none of the creates takes them.
//!
//! ## Whose the identity is
//!
//! "Ref returns the ARN" for all four, and that ARN carries an id Elastic Load Balancing
//! ASSIGNS (`…/loadbalancer/app/<name>/<id>`), so the identity in force is the one the create
//! answered ([`crate::state::template::identity_is_service_assigned`]). The load balancer's
//! and the target group's NAME is still CloudFormation's — the naming rules compute it
//! (`rules(32, …)`) and the create is made under it — so the name sent is the
//! `LoadBalancerName`/`TargetGroupName` attribute the naming rules gave the record.
//!
//! ## What the stack waits for
//!
//! `CreateLoadBalancer` answers the load balancer `provisioning`, and Elastic Load Balancing
//! reports when it is `active`, so the stack holds the resource's creation open until it is
//! ([`readiness`]). That wait is also what makes a declaration reading the load balancer's
//! attributes — a record set aliasing its `DNSName` and `CanonicalHostedZoneID` — resolve
//! against the values that service really reports ([`ready_attributes`]). A target group and
//! a listener and a rule are in force as their create answers.
//!
//! ## What is refused
//!
//! A declared property this module does not send is REFUSED rather than dropped
//! ([`query_members`]), so a resource is never reported created with less than its
//! declaration asked for. A changed declaration of an existing resource is reported as not
//! applied ([`super::Owner::update`]): no `Modify…` path is wired here yet.

use std::collections::BTreeMap;

use serde_json::Value;

use super::{call_query, xml_scalar_children, Created, Readiness, Refusal, Removal};
use crate::state::provisioner::{push_list, push_tag_list, query_members, tags_of, QueryMember};
use crate::state::StoredResource;

/// The resource types this module provisions.
pub(super) const ELB_LOAD_BALANCER: &str = "AWS::ElasticLoadBalancingV2::LoadBalancer";
pub(super) const ELB_TARGET_GROUP: &str = "AWS::ElasticLoadBalancingV2::TargetGroup";
pub(super) const ELB_LISTENER: &str = "AWS::ElasticLoadBalancingV2::Listener";
pub(super) const ELB_LISTENER_RULE: &str = "AWS::ElasticLoadBalancingV2::ListenerRule";

/// Elastic Load Balancing v2's signing name and the API version an awsQuery request names
/// beside the action, from its model (`sigv4 name: elasticloadbalancing`,
/// `version: 2015-12-01`).
const ELB_SIGNING_NAME: &str = "elasticloadbalancing";
const ELB_API_VERSION: &str = "2015-12-01";

/// The awsQuery error codes that service answers for a load balancer, a target group and a
/// listener it does not hold — a delete asking for a state that service is already in.
const LOAD_BALANCER_NOT_FOUND: &str = "LoadBalancerNotFound";
const TARGET_GROUP_NOT_FOUND: &str = "TargetGroupNotFound";
const LISTENER_NOT_FOUND: &str = "ListenerNotFound";
const RULE_NOT_FOUND: &str = "RuleNotFound";

/// The `LoadBalancerStateEnum` values a load balancer is reported in
/// (`smithy_query(query="shape",shape="LoadBalancerStateEnum")`): the one a create answers,
/// the two a load balancer serves traffic in, and the one nothing brings it out of.
const STATE_PROVISIONING: &str = "provisioning";
const STATE_ACTIVE: &str = "active";
const STATE_ACTIVE_IMPAIRED: &str = "active_impaired";

/// Which of this module's types one resource is.
///
/// Visible to the whole of this service's state module because it travels with
/// [`super::Owner`]: the algorithm resolves a type's owner once and passes it back here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::state) enum Kind {
    /// `AWS::ElasticLoadBalancingV2::LoadBalancer`.
    LoadBalancer,
    /// `AWS::ElasticLoadBalancingV2::TargetGroup`.
    TargetGroup,
    /// `AWS::ElasticLoadBalancingV2::Listener`.
    Listener,
    /// `AWS::ElasticLoadBalancingV2::ListenerRule`.
    ListenerRule,
}

/// The kind `resource_type` names, or `None` for a type this module does not own.
pub(super) fn kind_of(resource_type: &str) -> Option<Kind> {
    match resource_type {
        ELB_LOAD_BALANCER => Some(Kind::LoadBalancer),
        ELB_TARGET_GROUP => Some(Kind::TargetGroup),
        ELB_LISTENER => Some(Kind::Listener),
        ELB_LISTENER_RULE => Some(Kind::ListenerRule),
        _ => None,
    }
}

/// The `AWS::ElasticLoadBalancingV2::LoadBalancer` properties `CreateLoadBalancer` takes under
/// the SAME member name (AWS's CloudFormation resource reference for the type read against
/// `smithy_query(query="operation",operation="CreateLoadBalancer")`). Each list is the
/// awsQuery default `member` element.
const LOAD_BALANCER_MEMBERS: &[(&str, QueryMember)] = &[
    ("Subnets", QueryMember::List("member")),
    ("SubnetMappings", QueryMember::List("member")),
    ("SecurityGroups", QueryMember::List("member")),
    ("Scheme", QueryMember::Scalar),
    ("Type", QueryMember::Scalar),
    ("IpAddressType", QueryMember::Scalar),
    ("EnablePrefixForIpv6SourceNat", QueryMember::Scalar),
];

/// The load balancer properties another part of the create carries: the name (the one the
/// naming rules decided), the tags (with the stack's own propagated), the IPAM pool (a member
/// of the `IpamPools` structure rather than a member of its own), and the attributes, which
/// `ModifyLoadBalancerAttributes` writes once the load balancer exists.
const LOAD_BALANCER_NOT_SENT: &[&str] =
    &["Name", "Tags", "Ipv4IpamPoolId", "LoadBalancerAttributes"];

/// The `AWS::ElasticLoadBalancingV2::TargetGroup` properties `CreateTargetGroup` takes under
/// the SAME member name (the same reference read against
/// `smithy_query(query="operation",operation="CreateTargetGroup")`).
const TARGET_GROUP_MEMBERS: &[(&str, QueryMember)] = &[
    ("Protocol", QueryMember::Scalar),
    ("ProtocolVersion", QueryMember::Scalar),
    ("Port", QueryMember::Scalar),
    ("VpcId", QueryMember::Scalar),
    ("HealthCheckProtocol", QueryMember::Scalar),
    ("HealthCheckPort", QueryMember::Scalar),
    ("HealthCheckEnabled", QueryMember::Scalar),
    ("HealthCheckPath", QueryMember::Scalar),
    ("HealthCheckIntervalSeconds", QueryMember::Scalar),
    ("HealthCheckTimeoutSeconds", QueryMember::Scalar),
    ("HealthyThresholdCount", QueryMember::Scalar),
    ("UnhealthyThresholdCount", QueryMember::Scalar),
    ("Matcher", QueryMember::Structure),
    ("TargetType", QueryMember::Scalar),
    ("IpAddressType", QueryMember::Scalar),
    ("TargetControlPort", QueryMember::Scalar),
];

/// The target group properties another call carries: the name and tags as for a load
/// balancer, the targets (`RegisterTargets`) and the attributes
/// (`ModifyTargetGroupAttributes`).
const TARGET_GROUP_NOT_SENT: &[&str] = &["Name", "Tags", "Targets", "TargetGroupAttributes"];

/// The `AWS::ElasticLoadBalancingV2::Listener` properties `CreateListener` takes under the
/// SAME member name (the same reference read against
/// `smithy_query(query="operation",operation="CreateListener")`). A default action's own
/// members — `Type`, `TargetGroupArn`, `ForwardConfig`, `RedirectConfig`, … — are spelled
/// identically on both sides too, so the walk writes them to their leaves.
const LISTENER_MEMBERS: &[(&str, QueryMember)] = &[
    ("LoadBalancerArn", QueryMember::Scalar),
    ("Protocol", QueryMember::Scalar),
    ("Port", QueryMember::Scalar),
    ("SslPolicy", QueryMember::Scalar),
    ("Certificates", QueryMember::List("member")),
    ("DefaultActions", QueryMember::List("member")),
    ("AlpnPolicy", QueryMember::List("member")),
    ("MutualAuthentication", QueryMember::Structure),
];

/// The listener property another call carries: its attributes
/// (`ModifyListenerAttributes`). The type publishes no `Tags` property.
const LISTENER_NOT_SENT: &[&str] = &["ListenerAttributes"];

/// The `AWS::ElasticLoadBalancingV2::ListenerRule` properties `CreateRule` takes under the
/// SAME member name (the same reference read against
/// `smithy_query(query="operation",operation="CreateRule")`); a condition's and an action's
/// own members are spelled identically on both sides too. The type publishes no `Tags`.
const LISTENER_RULE_MEMBERS: &[(&str, QueryMember)] = &[
    ("ListenerArn", QueryMember::Scalar),
    ("Priority", QueryMember::Scalar),
    ("Conditions", QueryMember::List("member")),
    ("Actions", QueryMember::List("member")),
    ("Transforms", QueryMember::List("member")),
];

/// Create the resource one declaration of these types asks for, in Elastic Load Balancing.
///
/// `Err` is that service's own refusal, which is what the resource fails with. A follow-up
/// call the create owes (the attributes, the targets) that is refused takes the resource it
/// just made away again, so a failed resource leaves nothing behind.
pub(super) async fn create(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    kind: Kind,
    resource: &StoredResource,
    propagated: &[(String, String)],
) -> Result<Created, Refusal> {
    match kind {
        Kind::LoadBalancer => create_load_balancer(ctx, region, resource, propagated).await,
        Kind::TargetGroup => create_target_group(ctx, region, resource, propagated).await,
        Kind::Listener => create_listener(ctx, region, resource).await,
        Kind::ListenerRule => create_listener_rule(ctx, region, resource).await,
    }
}

/// Delete the resource a stack created, addressed by the ARN Elastic Load Balancing minted for
/// it — this resource's physical id. One that service no longer holds is already gone.
///
/// Deleting a load balancer also deletes its listeners ("Deleting a load balancer also deletes
/// its listeners"), so a listener whose load balancer went first answers
/// [`LISTENER_NOT_FOUND`], which is the state its delete asks for — and a rule whose listener
/// went first answers [`RULE_NOT_FOUND`] the same way.
pub(super) async fn delete(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    kind: Kind,
    resource: &StoredResource,
) -> Result<(), Refusal> {
    let arn = resource.physical_resource_id.clone();
    let (action, member, not_found) = match kind {
        Kind::LoadBalancer => (
            "DeleteLoadBalancer",
            "LoadBalancerArn",
            LOAD_BALANCER_NOT_FOUND,
        ),
        Kind::TargetGroup => (
            "DeleteTargetGroup",
            "TargetGroupArn",
            TARGET_GROUP_NOT_FOUND,
        ),
        Kind::Listener => ("DeleteListener", "ListenerArn", LISTENER_NOT_FOUND),
        Kind::ListenerRule => ("DeleteRule", "RuleArn", RULE_NOT_FOUND),
    };
    match call(ctx, region, action, &[(member.to_string(), arn)]).await {
        Ok(_) => Ok(()),
        Err(refusal) if refusal.code == not_found => Ok(()),
        Err(refusal) => Err(refusal),
    }
}

/// Whether Elastic Load Balancing reports the created resource ready.
///
/// A load balancer is answered [`STATE_PROVISIONING`] and becomes [`STATE_ACTIVE`], so the
/// stack holds its creation open until it does; a state no wait brings it out of (`failed`, or
/// a load balancer that service holds none of) fails the resource with what that service
/// reports. A target group and a listener are in force as their create answers.
pub(super) async fn readiness(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    kind: Kind,
    physical_resource_id: &str,
) -> Result<Readiness, Refusal> {
    if kind != Kind::LoadBalancer {
        return Ok(Readiness::Ready);
    }
    let Some(described) = describe_load_balancer(ctx, region, physical_resource_id).await? else {
        return Ok(Readiness::Failed(format!(
            "Elastic Load Balancing holds no load balancer for {physical_resource_id}"
        )));
    };
    match load_balancer_state(&described).as_deref() {
        Some(STATE_ACTIVE | STATE_ACTIVE_IMPAIRED) => Ok(Readiness::Ready),
        Some(STATE_PROVISIONING) => Ok(Readiness::Pending(STATE_PROVISIONING.to_string())),
        Some(other) => Ok(Readiness::Failed(format!(
            "Elastic Load Balancing reports load balancer {physical_resource_id} in state {other}"
        ))),
        None => Ok(Readiness::Failed(format!(
            "Elastic Load Balancing reports no state for load balancer {physical_resource_id}"
        ))),
    }
}

/// The attributes Elastic Load Balancing publishes for a load balancer it NOW reports active,
/// read once the wait above comes through — so a declaration withheld behind it (a record set
/// aliasing its `DNSName` and `CanonicalHostedZoneID`) resolves against them.
pub(super) async fn ready_attributes(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    kind: Kind,
    physical_resource_id: &str,
) -> Result<BTreeMap<String, String>, Refusal> {
    if kind != Kind::LoadBalancer {
        return Ok(BTreeMap::new());
    }
    match describe_load_balancer(ctx, region, physical_resource_id).await? {
        Some(described) => Ok(load_balancer_attributes(&described)),
        None => Ok(BTreeMap::new()),
    }
}

/// Every delete here takes the resource away as it answers: Elastic Load Balancing reports no
/// state a deleted load balancer, target group or listener is still being removed in.
pub(super) fn removal() -> Removal {
    Removal::Gone
}

async fn create_load_balancer(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    resource: &StoredResource,
    propagated: &[(String, String)],
) -> Result<Created, Refusal> {
    let parameters = load_balancer_parameters(resource, propagated)?;
    let answered = call(ctx, region, "CreateLoadBalancer", &parameters).await?;
    let attributes = load_balancer_attributes(&answered);
    let arn = answered_arn(&attributes, "LoadBalancerArn", "CreateLoadBalancer")?;
    let follow_up = match attribute_parameters(resource, "LoadBalancerAttributes") {
        Some(mut attribute_parameters) => {
            attribute_parameters.insert(0, ("LoadBalancerArn".to_string(), arn.clone()));
            call(
                ctx,
                region,
                "ModifyLoadBalancerAttributes",
                &attribute_parameters,
            )
            .await
            .map(|_| ())
        }
        None => Ok(()),
    };
    if let Err(refusal) = follow_up {
        undo(ctx, region, "DeleteLoadBalancer", "LoadBalancerArn", &arn).await;
        return Err(refusal);
    }
    Ok(Created {
        physical_resource_id: Some(arn),
        attributes,
    })
}

async fn create_target_group(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    resource: &StoredResource,
    propagated: &[(String, String)],
) -> Result<Created, Refusal> {
    let parameters = target_group_parameters(resource, propagated)?;
    let answered = call(ctx, region, "CreateTargetGroup", &parameters).await?;
    let attributes = target_group_attributes(&answered);
    let arn = answered_arn(&attributes, "TargetGroupArn", "CreateTargetGroup")?;
    let follow_up = async {
        if let Some(mut attribute_parameters) =
            attribute_parameters(resource, "TargetGroupAttributes")
        {
            attribute_parameters.insert(0, ("TargetGroupArn".to_string(), arn.clone()));
            call(
                ctx,
                region,
                "ModifyTargetGroupAttributes",
                &attribute_parameters,
            )
            .await?;
        }
        if let Some(mut target_parameters) = targets_parameters(resource)? {
            target_parameters.insert(0, ("TargetGroupArn".to_string(), arn.clone()));
            call(ctx, region, "RegisterTargets", &target_parameters).await?;
        }
        Ok::<(), Refusal>(())
    }
    .await;
    if let Err(refusal) = follow_up {
        undo(ctx, region, "DeleteTargetGroup", "TargetGroupArn", &arn).await;
        return Err(refusal);
    }
    Ok(Created {
        physical_resource_id: Some(arn),
        attributes,
    })
}

async fn create_listener(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    resource: &StoredResource,
) -> Result<Created, Refusal> {
    let parameters = listener_parameters(resource)?;
    let answered = call(ctx, region, "CreateListener", &parameters).await?;
    let attributes = listener_attributes(&answered);
    let arn = answered_arn(&attributes, "ListenerArn", "CreateListener")?;
    if let Some(mut attribute_parameters) = attribute_parameters(resource, "ListenerAttributes") {
        attribute_parameters.insert(0, ("ListenerArn".to_string(), arn.clone()));
        if let Err(refusal) = call(
            ctx,
            region,
            "ModifyListenerAttributes",
            &attribute_parameters,
        )
        .await
        {
            undo(ctx, region, "DeleteListener", "ListenerArn", &arn).await;
            return Err(refusal);
        }
    }
    Ok(Created {
        physical_resource_id: Some(arn),
        attributes,
    })
}

async fn create_listener_rule(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    resource: &StoredResource,
) -> Result<Created, Refusal> {
    let parameters = query_members(
        &resource.properties,
        LISTENER_RULE_MEMBERS,
        &[],
        &[],
        &resource.resource_type,
    )?;
    let answered = call(ctx, region, "CreateRule", &parameters).await?;
    let attributes = listener_rule_attributes(&answered);
    let arn = answered_arn(&attributes, "RuleArn", "CreateRule")?;
    Ok(Created {
        physical_resource_id: Some(arn),
        attributes,
    })
}

/// The `CreateLoadBalancer` parameters a declaration is: the name the naming rules decided,
/// every member sent under its own name, the IPAM pool inside `IpamPools`, and the tag set.
fn load_balancer_parameters(
    resource: &StoredResource,
    propagated: &[(String, String)],
) -> Result<Vec<(String, String)>, Refusal> {
    let mut parameters = vec![(
        "Name".to_string(),
        decided_name(resource, "LoadBalancerName")?,
    )];
    parameters.extend(query_members(
        &resource.properties,
        LOAD_BALANCER_MEMBERS,
        &[],
        LOAD_BALANCER_NOT_SENT,
        &resource.resource_type,
    )?);
    if let Some(pool) = resource
        .properties
        .get("Ipv4IpamPoolId")
        .and_then(Value::as_str)
        .filter(|pool| !pool.is_empty())
    {
        parameters.push(("IpamPools.Ipv4IpamPoolId".to_string(), pool.to_string()));
    }
    push_tag_list(
        &mut parameters,
        "Tags",
        "member",
        &tags_of(&resource.properties, propagated),
    );
    Ok(parameters)
}

/// The `CreateTargetGroup` parameters a declaration is, built the way a load balancer's are.
fn target_group_parameters(
    resource: &StoredResource,
    propagated: &[(String, String)],
) -> Result<Vec<(String, String)>, Refusal> {
    let mut parameters = vec![(
        "Name".to_string(),
        decided_name(resource, "TargetGroupName")?,
    )];
    parameters.extend(query_members(
        &resource.properties,
        TARGET_GROUP_MEMBERS,
        &[],
        TARGET_GROUP_NOT_SENT,
        &resource.resource_type,
    )?);
    push_tag_list(
        &mut parameters,
        "Tags",
        "member",
        &tags_of(&resource.properties, propagated),
    );
    Ok(parameters)
}

/// The `CreateListener` parameters a declaration is: every member under its own name.
fn listener_parameters(resource: &StoredResource) -> Result<Vec<(String, String)>, Refusal> {
    query_members(
        &resource.properties,
        LISTENER_MEMBERS,
        &[],
        LISTENER_NOT_SENT,
        &resource.resource_type,
    )
}

/// The `Attributes` list a `Modify…Attributes` call takes, from the declared `property`
/// (`[{Key, Value}]`, the same shape on both sides), or `None` for a declaration stating none.
fn attribute_parameters(
    resource: &StoredResource,
    property: &str,
) -> Option<Vec<(String, String)>> {
    let declared = resource.properties.get(property)?;
    if declared.as_array().is_none_or(Vec::is_empty) {
        return None;
    }
    let mut parameters = Vec::new();
    push_list(&mut parameters, "Attributes", "member", declared, 0).ok()?;
    (!parameters.is_empty()).then_some(parameters)
}

/// The `Targets` list `RegisterTargets` takes, from the declared `Targets` (`[{Id, Port,
/// AvailabilityZone}]`, the same members on both sides), or `None` for a declaration stating
/// none.
fn targets_parameters(resource: &StoredResource) -> Result<Option<Vec<(String, String)>>, Refusal> {
    let Some(declared) = resource.properties.get("Targets") else {
        return Ok(None);
    };
    if declared.as_array().is_none_or(Vec::is_empty) {
        return Ok(None);
    }
    let mut parameters = Vec::new();
    push_list(&mut parameters, "Targets", "member", declared, 0)?;
    Ok(Some(parameters))
}

/// The name a load balancer or a target group is created under: the one the naming rules gave
/// the record as its `attribute` (the declared `Name`, or one CloudFormation generated).
fn decided_name(resource: &StoredResource, attribute: &str) -> Result<String, Refusal> {
    resource
        .attributes
        .get(attribute)
        .filter(|name| !name.is_empty())
        .cloned()
        .or_else(|| {
            resource
                .properties
                .get("Name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .map(str::to_string)
        })
        .ok_or_else(|| Refusal {
            code: "InvalidRequest".to_string(),
            message: format!("{} has no name to be created under", resource.resource_type),
        })
}

/// The ARN a create answered under `attribute`, or the refusal for an answer that identifies
/// nothing.
fn answered_arn(
    attributes: &BTreeMap<String, String>,
    attribute: &str,
    action: &str,
) -> Result<String, Refusal> {
    attributes.get(attribute).cloned().ok_or_else(|| Refusal {
        code: "InvalidRequest".to_string(),
        message: format!("{action} answered no {attribute}"),
    })
}

/// Take away a resource whose create's follow-up was refused. A refusal of THIS call changes
/// nothing about what the resource fails with, so it is not reported over the one that did.
async fn undo(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    action: &str,
    member: &str,
    arn: &str,
) {
    let _ = call(
        ctx,
        region,
        action,
        &[(member.to_string(), arn.to_string())],
    )
    .await;
}

/// One awsQuery call to Elastic Load Balancing v2.
async fn call(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    action: &str,
    parameters: &[(String, String)],
) -> Result<String, Refusal> {
    call_query(
        ctx,
        ELB_SIGNING_NAME,
        region,
        ELB_API_VERSION,
        action,
        parameters,
    )
    .await
}

/// What Elastic Load Balancing reports about the load balancer `arn`, or `None` for one it
/// does not hold.
async fn describe_load_balancer(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    arn: &str,
) -> Result<Option<String>, Refusal> {
    match call(
        ctx,
        region,
        "DescribeLoadBalancers",
        &[("LoadBalancerArns.member.1".to_string(), arn.to_string())],
    )
    .await
    {
        Ok(answered) => Ok(Some(answered)),
        Err(refusal) if refusal.code == LOAD_BALANCER_NOT_FOUND => Ok(None),
        Err(refusal) => Err(refusal),
    }
}

/// The first entry of the list an answer carries, as its scalar members: every answer read
/// here names ONE resource, which is the first `<member>` of the answer's own list.
fn first_entry(document: &str) -> ::serde_json::Map<String, Value> {
    xml_scalar_children(document, "member")
}

/// The scalar member `element` of an entry, where the answer carries a non-empty one.
fn reported(entry: &::serde_json::Map<String, Value>, element: &str) -> Option<String> {
    entry
        .get(element)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// The state a described load balancer is in, from its `State` structure's `Code`.
fn load_balancer_state(document: &str) -> Option<String> {
    reported(&xml_scalar_children(document, "State"), "Code")
}

/// The part of an ELB ARN after `segment` (`loadbalancer/`, `targetgroup/`), which is what
/// the type's `…FullName` attribute is documented as (`app/my-alb/50dc6c495c0c9188`).
fn full_name(arn: &str, segment: &str) -> Option<String> {
    arn.split_once(segment).map(|(_, rest)| rest.to_string())
}

/// The `Fn::GetAtt` attributes `AWS::ElasticLoadBalancingV2::LoadBalancer` publishes, as a
/// `CreateLoadBalancer` or `DescribeLoadBalancers` answer reports them. `SecurityGroups` is
/// list-valued, so it is not carried. The service's member is `CanonicalHostedZoneId`; the
/// type's attribute is spelled `CanonicalHostedZoneID`.
fn load_balancer_attributes(document: &str) -> BTreeMap<String, String> {
    let entry = first_entry(document);
    let mut attributes = BTreeMap::new();
    for (attribute, element) in [
        ("LoadBalancerArn", "LoadBalancerArn"),
        ("DNSName", "DNSName"),
        ("CanonicalHostedZoneID", "CanonicalHostedZoneId"),
        ("LoadBalancerName", "LoadBalancerName"),
    ] {
        if let Some(value) = reported(&entry, element) {
            attributes.insert(attribute.to_string(), value);
        }
    }
    if let Some(name) = attributes
        .get("LoadBalancerArn")
        .and_then(|arn| full_name(arn, ":loadbalancer/"))
    {
        attributes.insert("LoadBalancerFullName".to_string(), name);
    }
    attributes
}

/// The `Fn::GetAtt` attributes `AWS::ElasticLoadBalancingV2::TargetGroup` publishes, as a
/// `CreateTargetGroup` answer reports them. `LoadBalancerArns` is list-valued, so it is not
/// carried. The full name keeps its `targetgroup/` prefix, as the type documents it
/// (`targetgroup/my-target-group/cbf133c568e0d028`).
fn target_group_attributes(document: &str) -> BTreeMap<String, String> {
    let entry = first_entry(document);
    let mut attributes = BTreeMap::new();
    for element in ["TargetGroupArn", "TargetGroupName"] {
        if let Some(value) = reported(&entry, element) {
            attributes.insert(element.to_string(), value);
        }
    }
    if let Some(name) = attributes
        .get("TargetGroupArn")
        .and_then(|arn| full_name(arn, ":"))
        .and_then(|rest| rest.rsplit_once(':').map(|(_, path)| path.to_string()))
    {
        attributes.insert("TargetGroupFullName".to_string(), name);
    }
    attributes
}

/// The `Fn::GetAtt` attribute `AWS::ElasticLoadBalancingV2::Listener` publishes, as a
/// `CreateListener` answer reports it.
fn listener_attributes(document: &str) -> BTreeMap<String, String> {
    let entry = first_entry(document);
    let mut attributes = BTreeMap::new();
    if let Some(arn) = reported(&entry, "ListenerArn") {
        attributes.insert("ListenerArn".to_string(), arn);
    }
    attributes
}

/// The `Fn::GetAtt` attributes `AWS::ElasticLoadBalancingV2::ListenerRule` publishes, as a
/// `CreateRule` answer reports them: its ARN, and whether it is its listener's default rule
/// (never, for a rule a template declares — that one is created with the listener).
fn listener_rule_attributes(document: &str) -> BTreeMap<String, String> {
    let entry = first_entry(document);
    let mut attributes = BTreeMap::new();
    for element in ["RuleArn", "IsDefault"] {
        if let Some(value) = reported(&entry, element) {
            attributes.insert(element.to_string(), value);
        }
    }
    attributes
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn declared(
        resource_type: &str,
        properties: Value,
        name_attribute: Option<(&str, &str)>,
    ) -> StoredResource {
        let mut attributes = BTreeMap::new();
        if let Some((attribute, name)) = name_attribute {
            attributes.insert(attribute.to_string(), name.to_string());
        }
        StoredResource {
            logical_id: "Declared".to_string(),
            resource_type: resource_type.to_string(),
            physical_resource_id: "stand-in".to_string(),
            attributes,
            metadata: None,
            properties,
            materialised: false,
            deletion_policy: None,
        }
    }

    fn has(parameters: &[(String, String)], name: &str, value: &str) -> bool {
        parameters.iter().any(|(n, v)| n == name && v == value)
    }

    #[test]
    fn a_load_balancer_declaration_becomes_create_load_balancer_parameters() {
        let resource = declared(
            ELB_LOAD_BALANCER,
            json!({
                "Subnets": ["subnet-a", "subnet-b"],
                "SecurityGroups": ["sg-1"],
                "Scheme": "internet-facing",
                "Tags": [{"Key": "team", "Value": "core"}],
                "LoadBalancerAttributes": [{"Key": "idle_timeout.timeout_seconds", "Value": "60"}],
            }),
            Some(("LoadBalancerName", "stack-ALB-ABC123")),
        );
        let propagated = vec![(
            "aws:cloudformation:stack-name".to_string(),
            "stack".to_string(),
        )];
        let parameters = load_balancer_parameters(&resource, &propagated).expect("parameters");
        for (name, value) in [
            ("Name", "stack-ALB-ABC123"),
            ("Subnets.member.1", "subnet-a"),
            ("Subnets.member.2", "subnet-b"),
            ("SecurityGroups.member.1", "sg-1"),
            ("Scheme", "internet-facing"),
            ("Tags.member.1.Key", "team"),
            ("Tags.member.1.Value", "core"),
            ("Tags.member.2.Key", "aws:cloudformation:stack-name"),
        ] {
            assert!(
                has(&parameters, name, value),
                "case {name}: expected {value:?} in {parameters:?}"
            );
        }
        assert!(
            !parameters
                .iter()
                .any(|(n, _)| n.starts_with("LoadBalancerAttributes")),
            "attributes travel on ModifyLoadBalancerAttributes, got {parameters:?}"
        );
        let attributes =
            attribute_parameters(&resource, "LoadBalancerAttributes").expect("attributes");
        assert!(has(
            &attributes,
            "Attributes.member.1.Key",
            "idle_timeout.timeout_seconds"
        ));
        assert!(has(&attributes, "Attributes.member.1.Value", "60"));
    }

    #[test]
    fn an_unsent_load_balancer_property_is_refused() {
        let resource = declared(
            ELB_LOAD_BALANCER,
            json!({"Subnets": ["subnet-a"], "MinimumLoadBalancerCapacity": {"CapacityUnits": 100}}),
            Some(("LoadBalancerName", "lb")),
        );
        let refused = load_balancer_parameters(&resource, &[]).expect_err("refused");
        assert!(
            refused.message.contains("MinimumLoadBalancerCapacity"),
            "expected the refusal to name the property, got {refused:?}"
        );
    }

    #[test]
    fn a_target_group_declaration_becomes_create_and_register_parameters() {
        let resource = declared(
            ELB_TARGET_GROUP,
            json!({
                "Port": 3000,
                "Protocol": "HTTP",
                "VpcId": "vpc-1",
                "HealthCheckPath": "/health",
                "HealthCheckEnabled": true,
                "Matcher": {"HttpCode": "200-299"},
                "Targets": [{"Id": "i-1", "Port": 3000}],
            }),
            Some(("TargetGroupName", "stack-TG-XYZ")),
        );
        let parameters = target_group_parameters(&resource, &[]).expect("parameters");
        for (name, value) in [
            ("Name", "stack-TG-XYZ"),
            ("Port", "3000"),
            ("HealthCheckEnabled", "true"),
            ("Matcher.HttpCode", "200-299"),
        ] {
            assert!(
                has(&parameters, name, value),
                "case {name}: expected {value:?} in {parameters:?}"
            );
        }
        let targets = targets_parameters(&resource).expect("ok").expect("targets");
        assert!(has(&targets, "Targets.member.1.Id", "i-1"));
        assert!(has(&targets, "Targets.member.1.Port", "3000"));
    }

    #[test]
    fn a_listener_default_action_is_written_to_its_leaves() {
        let resource = declared(
            ELB_LISTENER,
            json!({
                "LoadBalancerArn": "arn:lb",
                "Port": 80,
                "Protocol": "HTTP",
                "DefaultActions": [{
                    "Type": "forward",
                    "ForwardConfig": {"TargetGroups": [{"TargetGroupArn": "arn:tg", "Weight": 1}]},
                }],
            }),
            None,
        );
        let parameters = listener_parameters(&resource).expect("parameters");
        for (name, value) in [
            ("LoadBalancerArn", "arn:lb"),
            ("Port", "80"),
            ("DefaultActions.member.1.Type", "forward"),
            (
                "DefaultActions.member.1.ForwardConfig.TargetGroups.member.1.TargetGroupArn",
                "arn:tg",
            ),
        ] {
            assert!(
                has(&parameters, name, value),
                "case {name}: expected {value:?} in {parameters:?}"
            );
        }
    }

    #[test]
    fn the_published_attributes_are_read_from_the_answers() {
        let load_balancer = "<CreateLoadBalancerResponse><CreateLoadBalancerResult><LoadBalancers><member>\
            <LoadBalancerArn>arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/my-alb/50dc6c495c0c9188</LoadBalancerArn>\
            <DNSName>my-alb-1.us-east-1.elb.amazonaws.com</DNSName>\
            <CanonicalHostedZoneId>Z35SXDOTRQ7X7K</CanonicalHostedZoneId>\
            <LoadBalancerName>my-alb</LoadBalancerName>\
            <State><Code>provisioning</Code></State>\
            <AvailabilityZones><member><ZoneName>us-east-1a</ZoneName></member></AvailabilityZones>\
            </member></LoadBalancers></CreateLoadBalancerResult></CreateLoadBalancerResponse>";
        let attributes = load_balancer_attributes(load_balancer);
        assert_eq!(
            attributes.get("CanonicalHostedZoneID").map(String::as_str),
            Some("Z35SXDOTRQ7X7K")
        );
        assert_eq!(
            attributes.get("DNSName").map(String::as_str),
            Some("my-alb-1.us-east-1.elb.amazonaws.com")
        );
        assert_eq!(
            attributes.get("LoadBalancerName").map(String::as_str),
            Some("my-alb")
        );
        assert_eq!(
            attributes.get("LoadBalancerFullName").map(String::as_str),
            Some("app/my-alb/50dc6c495c0c9188")
        );
        assert_eq!(
            load_balancer_state(load_balancer).as_deref(),
            Some("provisioning")
        );

        let target_group = "<CreateTargetGroupResponse><CreateTargetGroupResult><TargetGroups><member>\
            <TargetGroupArn>arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/my-tg/cbf133c568e0d028</TargetGroupArn>\
            <TargetGroupName>my-tg</TargetGroupName>\
            </member></TargetGroups></CreateTargetGroupResult></CreateTargetGroupResponse>";
        let attributes = target_group_attributes(target_group);
        assert_eq!(
            attributes.get("TargetGroupFullName").map(String::as_str),
            Some("targetgroup/my-tg/cbf133c568e0d028")
        );
        assert_eq!(
            attributes.get("TargetGroupName").map(String::as_str),
            Some("my-tg")
        );
    }
}
