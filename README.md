# MCP SSE Authorizer

A command-line tool to authenticate with Model Context Protocol (MCP) Server-Sent Events (SSE) endpoints.

## Overview

The MCP SSE Authorizer handles the OAuth 2.1 authentication flow for MCP SSE endpoints and outputs the required HTTP headers for subsequent requests. This tool simplifies the authorization process by:

1. Discovering authorization server metadata
2. Performing dynamic client registration when supported
3. Implementing OAuth 2.1 authorization code flow with PKCE
4. Generating and outputting the necessary HTTP headers for authenticated MCP requests

## Requirements

- Python 3.13 or higher
- `requests` package (>=2.32.3)

## Installation

You can install the package using uv:

```bash
# Install as a regular package
uv pip install mcp-sse-authorizer
```

Or run directly from the GitHub repository without installing:

```bash
uv tool run github.com/lnagel/mcp-sse-authorizer [MCP_URL] [--client-id CLIENT_ID]
```

Or clone the repository:

```bash
git clone https://github.com/lnagel/mcp-sse-authorizer.git
cd mcp-sse-authorizer
uv pip install -e .
```

## Usage

Run the script directly:

```bash
python mcp_authorizer.py [MCP_URL] [--client-id CLIENT_ID]
```

Or if installed via uv:

```bash
uv run mcp_authorizer.py [MCP_URL] [--client-id CLIENT_ID]
```

Or run directly from GitHub:

```bash
uv tool run github.com/lnagel/mcp-sse-authorizer [MCP_URL] [--client-id CLIENT_ID]
```

### Arguments

- `MCP_URL`: The MCP SSE endpoint URL (required)
- `--client-id`: Pre-registered OAuth client ID (optional, required if dynamic registration is not supported)

### Example

```bash
# Running the script directly
python mcp_authorizer.py https://mcp.example.com/v1/sse

# Running from GitHub repository
uv tool run github.com/lnagel/mcp-sse-authorizer https://mcp.example.com/v1/sse
```

If the MCP server supports dynamic client registration, the tool will register a new client automatically. Otherwise, you'll need to provide a pre-registered client ID:

```bash
uv tool run github.com/lnagel/mcp-sse-authorizer https://mcp.example.com/v1/sse --client-id your_client_id
```

## Authorization Flow

The tool implements the OAuth 2.1 authorization code flow with PKCE:

1. Discovers authorization server metadata or falls back to default endpoints
2. Performs dynamic client registration if supported
3. Launches a browser for user authentication
4. Starts a local callback server to receive the authorization code
5. Exchanges the authorization code for an access token
6. Outputs the required HTTP headers for authenticated requests

## Features

- **Metadata Discovery**: Implements OAuth 2.0 Authorization Server Metadata protocol to discover endpoints
- **Dynamic Registration**: Supports OAuth 2.0 Dynamic Client Registration Protocol for seamless setup
- **PKCE Support**: Implements Proof Key for Code Exchange for enhanced security
- **Local Callback Server**: Handles the OAuth callback automatically via a temporary local server
- **Header Generation**: Outputs ready-to-use HTTP headers for authenticated requests

## Security Considerations

- All authorization is performed using current OAuth 2.1 best practices
- PKCE is used to prevent authorization code interception
- The tool operates as a public OAuth client
- All communication with the authorization server is performed over HTTPS
- The temporary local callback server only runs during the authorization process

## Protocol Compliance

This tool complies with the following specifications:

- [OAuth 2.1 IETF DRAFT](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12)
- [OAuth 2.0 Authorization Server Metadata (RFC8414)](https://datatracker.ietf.org/doc/html/rfc8414)
- [OAuth 2.0 Dynamic Client Registration Protocol (RFC7591)](https://datatracker.ietf.org/doc/html/rfc7591)

For more details on the MCP authorization specification, see [authorization.mdx](authorization.mdx).

## License

[License information]

## Contributing

[Contributing information]