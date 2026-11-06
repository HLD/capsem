// Generated from Capsem OpenAPI. Do not edit.

import {z} from "zod";
import type {CredentialInjectRequest} from "../models/CredentialInjectRequest.js";
import {CredentialInjectProviderSchema} from "./CredentialInjectProvider.js";
import {CredentialStorageSchema} from "./CredentialStorage.js";

export const CredentialInjectRequestSchema: z.ZodType<CredentialInjectRequest> = z.strictObject({
  "binding": z.string().nullable().exactOptional(),
  "provider": z.lazy(() => CredentialInjectProviderSchema),
  "storage": z.lazy(() => CredentialStorageSchema).exactOptional(),
  "value": z.string(),
});
