#!/usr/bin/env node

import { fileURLToPath } from "node:url";
import { runServiceMain } from "@chaitin-ai/octobus-sdk";

import { service } from "../qianxin__hunter_public/src/service.js";

runServiceMain(service, {
  entryFile: fileURLToPath(new URL("../qianxin__hunter_public/bin/qianxin-hunter-public.js", import.meta.url)),
});
