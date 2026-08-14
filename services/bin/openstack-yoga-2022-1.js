#!/usr/bin/env node
import { fileURLToPath } from "node:url";
import { runServiceMain } from "@chaitin-ai/octobus-sdk";
import { service } from "../openinfra__openstack-yoga_2022-1/src/service.js";

await runServiceMain(service, {
  entryFile: fileURLToPath(new URL("../openinfra__openstack-yoga_2022-1/bin/openstack-yoga-2022-1.js", import.meta.url)),
});
