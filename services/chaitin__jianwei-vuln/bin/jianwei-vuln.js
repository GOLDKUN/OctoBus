#!/usr/bin/env node

import { runServiceMain } from "@chaitin-ai/octobus-sdk";
import { fileURLToPath } from "node:url";

import { service } from "../src/service.js";

runServiceMain(service, {
  entryFile: fileURLToPath(new URL("./jianwei-vuln.js", import.meta.url)),
});
