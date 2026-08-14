import { defineService } from "@chaitin-ai/octobus-sdk";

import { handlers } from "./qianxin-hunter-public.js";

export { handlers } from "./qianxin-hunter-public.js";

export const service = defineService({ handlers });
