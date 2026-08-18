#!/usr/bin/env node

import { fileURLToPath } from "node:url";
import { runServiceMain } from "@chaitin-ai/octobus-sdk";

import { service } from "../sangfor__xdr/src/service.js";

runServiceMain(service, {
  entryFile: fileURLToPath(new URL("../sangfor__xdr/bin/sangfor-xdr.js", import.meta.url)),
});
