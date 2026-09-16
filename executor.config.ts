import { defineExecutorConfig } from "@executor-js/sdk";
import { openApiHttpPlugin } from "@executor-js/plugin-openapi/api";
import {
  googleCatalog,
  googleDiscoveryAdapter,
} from "@executor-js/plugin-openapi/providers/google";
import {
  microsoftCatalog,
  microsoftGraphAdapter,
} from "@executor-js/plugin-openapi/providers/microsoft";
import { mcpHttpPlugin } from "@executor-js/plugin-mcp/api";
import { graphqlHttpPlugin } from "@executor-js/plugin-graphql/api";
import { onepasswordHttpPlugin } from "@executor-js/plugin-onepassword/api";
import { encryptedSecretsPlugin } from "@executor-js/plugin-encrypted-secrets";
import { toolkitsPlugin } from "@executor-js/plugin-toolkits/server";

import { resolveSecretKey } from "./src/config";

interface SelfHostPluginDeps {
  readonly activeToolkitSlug?: string;
  readonly allowLocalNetwork?: boolean;
}

export default defineExecutorConfig({
  plugins: ({ activeToolkitSlug }: SelfHostPluginDeps = {}) =>
    [
      openApiHttpPlugin({
        presets: [...googleCatalog, ...microsoftCatalog],
        specFormats: [googleDiscoveryAdapter, microsoftGraphAdapter],
      }),
      mcpHttpPlugin({
        dangerouslyAllowStdioMCP: process.env.EXECUTOR_ALLOW_STDIO_MCP === "true",
      }),
      graphqlHttpPlugin(),
      toolkitsPlugin({ activeToolkitSlug }),
      onepasswordHttpPlugin(),
      encryptedSecretsPlugin({ key: resolveSecretKey() }),
    ] as const,
});
