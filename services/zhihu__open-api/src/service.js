import { defineService } from '@chaitin-ai/octobus-sdk';

import { handlers } from './zhihu-open-api.js';

export { handlers } from './zhihu-open-api.js';

export const service = defineService({ handlers });
