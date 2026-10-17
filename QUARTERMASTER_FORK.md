# Quartermaster-enabled OPR fork

This document describes the fork-specific behavior in this checkout relative
to the upstream OpenCode Permission Reviewer (OPR). It is not a claim that
upstream OPR supports these Quartermaster integrations.

## What this fork adds

- **Named-plan selection for chat reviews (V2).** When trusted
  `planRouting` is enabled, OPR asks Quartermaster to select a model from the
  named plan before each isolated reviewer session. This also applies when Jev
  asks for a chat-model reasoning escalation. OPR applies the returned model;
  no reviewer agent binding or model-switching hook is used.
- **Jev module routing.** When trusted `moduleRouting` is enabled for a Jev
  primary review, OPR asks Quartermaster for an `opr-jev` module candidate.
  OPR calls Jev directly and reports a rate limit so Quartermaster can apply
  its configured cooldown. This is separate from named chat plans.
- **Windows support and diagnostics.** The fork includes Windows portability
  fixes and optional debug request diagnostics that record selected request
  metadata (such as tool names and approved header presence), not prompt or
  request-body contents.

Both routing features are opt-in in trusted global reviewer configuration.
For chat plans, the configured model list is an exact allowlist: it authorizes
which models may receive review evidence, including paid models. An unavailable
plan, invalid result, or unlisted model fails closed through OPR's escalation
policy; OPR does not silently fall back to its static model. Without chat-plan
routing, OPR uses its configured reviewer model. OpenCode V1 does not support
named-plan routing.

## Why use this arrangement?

The goal is to let Quartermaster choose an eligible reviewer model from one
named plan for each review, while keeping model validation and the permission
decision inside OPR. Jev remains a specialized primary reviewer with its own
module profile and cooldown behavior; only a Jev reasoning escalation uses the
chat reviewer plan. Keeping those paths separate avoids treating a chat-model
plan as Jev's rate-limit or usage policy.

The reviewer session remains isolated and tool-free: operational tool
execution is blocked, and only the decision-result tool is exposed when the
output format requires it. The selection RPC is advice only; OPR validates the
result against trusted configuration and creates the session with the chosen
model. A configured model's actual provider availability must still be tested;
Quartermaster selection does not guarantee that the provider will accept it.

For setup and the full configuration contract, see the README sections on
[named-plan selection](./README.md#optional-quartermaster-named-plan-selection-v2)
and [Jev module routing](./README.md#quartermaster-module-routing-for-jev).
