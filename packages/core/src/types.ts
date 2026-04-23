// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
import type { OpenAPIV3, OpenAPIV3_1 } from 'openapi-types';

export type OpenAPIDocument = OpenAPIV3.Document | OpenAPIV3_1.Document;

export type Diagnostic = {
  level: 'info' | 'warn' | 'error';
  path: string;
  message: string;
};

export type NormalizedParameter = {
  name: string;
  in: 'query' | 'header' | 'path' | 'cookie';
  required: boolean;
  deprecated: boolean;
  schema?: NormalizedSchema;
  style?: string;
  explode?: boolean;
};

export type NormalizedSchema = {
  type?: 'string' | 'number' | 'integer' | 'boolean' | 'array' | 'object' | 'null';
  format?: string;
  enum?: (string | number | boolean | null)[];
  pattern?: string;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  nullable?: boolean;
  items?: NormalizedSchema;
};

export type NormalizedSecurityScheme = {
  name: string;
  type: 'apiKey' | 'http' | 'oauth2' | 'openIdConnect' | 'mutualTLS';
  in?: 'header' | 'query' | 'cookie';
  headerName?: string;
  scheme?: string;
  bearerFormat?: string;
};

export type NormalizedSecurityRequirement = {
  schemeName: string;
  scopes: string[];
};

export type NormalizedOperation = {
  operationId?: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS' | 'HEAD' | 'TRACE';
  path: string;
  pathRegex: string;
  parameters: NormalizedParameter[];
  requestContentTypes: string[];
  requestBodyRequired: boolean;
  security: NormalizedSecurityRequirement[][] | null;
  deprecated: boolean;
  tags: string[];
  xCoraza: Record<string, unknown>;
};

export type NormalizedServer = {
  url: string;
  host?: string;
  basePath?: string;
};

export type NormalizedSpec = {
  title: string;
  version: string;
  hash: string;
  servers: NormalizedServer[];
  operations: NormalizedOperation[];
  securitySchemes: Record<string, NormalizedSecurityScheme>;
  globalSecurity: NormalizedSecurityRequirement[][] | null;
  diagnostics: Diagnostic[];
};