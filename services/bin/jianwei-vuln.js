#!/usr/bin/env node

import { fileURLToPath } from "node:url";
import { runServiceMain } from "@chaitin-ai/octobus-sdk";

import { service } from "../chaitin__jianwei-vuln/src/service.js";

runServiceMain(service, {
  entryFile: fileURLToPath(new URL("../chaitin__jianwei-vuln/bin/jianwei-vuln.js", import.meta.url)),
});
