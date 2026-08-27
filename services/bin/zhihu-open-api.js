#!/usr/bin/env node

import { fileURLToPath } from "node:url";
import { runServiceMain } from "@chaitin-ai/octobus-sdk";

import { service } from "../zhihu__open-api/src/service.js";

runServiceMain(service, {
  entryFile: fileURLToPath(new URL("../zhihu__open-api/bin/zhihu-open-api.js", import.meta.url)),
});
