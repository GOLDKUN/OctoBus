import { defineService } from "@chaitin-ai/octobus-sdk";

import { handlers } from "./jianwei-vuln.js";

export { handlers } from "./jianwei-vuln.js";

export const service = defineService({ handlers });
