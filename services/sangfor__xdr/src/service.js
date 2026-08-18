import { defineService } from "@chaitin-ai/octobus-sdk";
import { handlers as implementationHandlers } from "./sangfor-xdr.js";

// The SDK invokes handlers with one context object whose `request` member
// contains the decoded protobuf request. Keep two-argument invocation support
// for focused unit tests and embedders.
export const handlers = Object.fromEntries(
  Object.entries(implementationHandlers).map(([name, handler]) => [
    name,
    (requestOrContext, maybeContext) => maybeContext === undefined
      ? handler(requestOrContext?.request ?? {}, requestOrContext ?? {})
      : handler(requestOrContext ?? {}, maybeContext ?? {}),
  ]),
);

export const service = defineService({ handlers });
