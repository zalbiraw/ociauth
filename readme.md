# OCI Auth Plugin

Traefik plugin for Oracle Cloud Infrastructure (OCI) Instance Principal authentication. This plugin adds OCI signature authentication headers to HTTP requests, allowing them to authenticate with OCI services.

## Installation

### Static Configuration

```yaml
experimental:
  plugins:
    ociauth:
      moduleName: github.com/zalbiraw/ociauth
      version: v0.0.1
```

## Configuration

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `authType` | string | `"instance_principal"` | No | Authentication method. Only `"instance_principal"` is supported. |
| `serviceName` | string | `"generativeai"` | No | OCI service name. Only `"generativeai"` is currently supported. |
| `region` | string | - | Yes | OCI region for the service endpoint (e.g., `"us-chicago-1"`, `"us-ashburn-1"`, `"eu-frankfurt-1"`). |

## Usage

### Dynamic Configuration

```yaml
http:
  middlewares:
    oci-auth:
      plugin:
        ociauth:
          authType: "instance_principal"
          serviceName: "generativeai"
          region: "us-chicago-1"
  routers:
    my-service:
      rule: "Host(`api.example.com`)"
      service: my-service
      middlewares:
        - oci-auth
```

## Features

- **Instance Principal Authentication**: Automatically authenticates requests using OCI Instance Principal credentials
- **Automatic Host Setting**: Sets the correct OCI service endpoint based on service name and region
- **Header Management**: Adds required OCI signature headers (Date, Content-Type, Content-Length, X-Content-SHA256, Authorization)
- **Consistent Signature Calculation**: Ensures proper host header handling for signature validation

## Requirements

- The plugin must run on an OCI compute instance with Instance Principal authentication configured
- The compute instance must have appropriate IAM policies to access the target OCI service
