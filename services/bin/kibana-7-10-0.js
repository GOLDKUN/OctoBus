#!/usr/bin/env node

import { fileURLToPath } from "node:url";
import { runServiceMain } from "@chaitin-ai/octobus-sdk";

import { service } from "../elastic__kibana_7-10-0/src/service.js";

runServiceMain(service, {
  entryFile: fileURLToPath(new URL("../elastic__kibana_7-10-0/bin/kibana-7-10-0.js", import.meta.url)),
});
