use super::invocation::HostInvocationContext;

pub fn format_context_tag(ctx: &HostInvocationContext) -> String {
    format!(
        "host:{};version:{};cycle-id:{}",
        ctx.host_id, ctx.host_version, ctx.cycle_id
    )
}
