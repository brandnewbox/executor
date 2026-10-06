import { loadConfig } from "./config";
import { log } from "./grants";
import { createHandler } from "./oauth";

const config = loadConfig();
const handle = createHandler(config);

const server = Bun.serve({ port: config.port, hostname: "0.0.0.0", fetch: handle });
log("listening", { port: server.port, publicUrl: config.publicUrl.toString(), rancher: config.rancherUrl.toString() });

for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.on(signal, () => {
    server.stop();
    process.exit(0);
  });
}
