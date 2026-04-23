// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
// Inline YAML strings so the browser bundle does not need file-system access.
export const petstoreYaml = `openapi: 3.0.3
info:
  title: Petstore
  version: 1.0.0
servers:
  - url: https://petstore.example.com/api/v1
components:
  securitySchemes:
    ApiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
    BearerAuth:
      type: http
      scheme: bearer
security:
  - ApiKeyAuth: []
paths:
  /pets:
    get:
      operationId: listPets
      parameters:
        - { name: limit, in: query, schema: { type: integer, minimum: 1, maximum: 100 } }
        - { name: status, in: query, required: true, schema: { type: string, enum: [available, pending, sold] } }
      responses: { '200': { description: OK } }
    post:
      operationId: createPet
      security: [{ BearerAuth: [] }]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              properties:
                name: { type: string, minLength: 1, maxLength: 64 }
                tag: { type: string }
      responses: { '201': { description: Created } }
  /pets/{petId}:
    parameters:
      - { name: petId, in: path, required: true, schema: { type: string, format: uuid } }
    get:
      operationId: getPet
      responses: { '200': { description: OK } }
    delete:
      operationId: deletePet
      deprecated: true
      responses: { '204': { description: No Content } }
  /health:
    get:
      operationId: health
      security: []
      responses: { '200': { description: OK } }
`;

export const minimalYaml = `openapi: 3.0.3
info:
  title: Minimal
  version: 0.1.0
paths:
  /ping:
    get:
      operationId: ping
      responses: { '200': { description: OK } }
`;

export const samples = {
  petstore: { name: 'Petstore', yaml: petstoreYaml },
  minimal: { name: 'Minimal', yaml: minimalYaml },
};