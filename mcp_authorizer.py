#!/usr/bin/env python3
"""
MCP Authorizer - A tool to authenticate with MCP SSE endpoints

This script handles the OAuth 2.1 authentication flow for MCP SSE endpoints
and outputs the required HTTP headers for subsequent requests.
"""

import argparse
import base64
import hashlib
import json
import os
import random
import requests
import string
import sys
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

class CallbackHandler(BaseHTTPRequestHandler):
    """Simple HTTP server to handle OAuth callback"""
    
    def do_GET(self):
        """Handle GET request containing the authorization code"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        # Parse the authorization code from the callback URL
        query_components = parse_qs(urlparse(self.path).query)
        if 'code' in query_components:
            code = query_components['code'][0]
            self.server.authorization_code = code
            response = "<html><body><h1>Authorization Successful</h1><p>You can now close this window.</p></body></html>"
        else:
            error = query_components.get('error', ['Unknown error'])[0]
            error_description = query_components.get('error_description', ['No description'])[0]
            self.server.authorization_code = None
            response = f"<html><body><h1>Authorization Failed</h1><p>Error: {error}</p><p>{error_description}</p></body></html>"
        
        self.wfile.write(response.encode())
        
    def log_message(self, format, *args):
        """Silence the default logging"""
        return

def generate_pkce_pair():
    """Generate a PKCE code verifier and challenge pair"""
    # Generate code verifier (random string between 43-128 chars)
    code_verifier = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(64))
    
    # Generate code challenge (BASE64URL-ENCODE(SHA256(ASCII(code_verifier))))
    code_challenge_digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge_digest).decode('ascii').rstrip('=')
    
    return code_verifier, code_challenge

def discover_auth_server_metadata(mcp_url):
    """Discover OAuth 2.0 Authorization Server Metadata"""
    # Parse the MCP URL to get the base URL
    parsed_url = urlparse(mcp_url)
    auth_base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    # Try to fetch the metadata
    metadata_url = f"{auth_base_url}/.well-known/oauth-authorization-server"
    
    try:
        headers = {"MCP-Protocol-Version": "2025-03-26"}  # Use the protocol version from the document
        response = requests.get(metadata_url, headers=headers)
        
        if response.status_code == 200:
            return response.json(), auth_base_url
        else:
            print(f"Metadata discovery failed with status code: {response.status_code}")
            # Fall back to default endpoints
            return {
                "authorization_endpoint": f"{auth_base_url}/authorize",
                "token_endpoint": f"{auth_base_url}/token",
                "registration_endpoint": f"{auth_base_url}/register"
            }, auth_base_url
    except requests.RequestException as e:
        print(f"Error during metadata discovery: {e}")
        # Fall back to default endpoints
        return {
            "authorization_endpoint": f"{auth_base_url}/authorize",
            "token_endpoint": f"{auth_base_url}/token",
            "registration_endpoint": f"{auth_base_url}/register"
        }, auth_base_url

def perform_dynamic_registration(registration_endpoint):
    """Perform dynamic client registration if supported"""
    try:
        # Prepare the registration request payload
        registration_data = {
            "client_name": "MCP Authorizer CLI",
            "redirect_uris": ["http://localhost:8000/callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"  # For public client
        }
        
        # Send the registration request
        response = requests.post(
            registration_endpoint,
            headers={"Content-Type": "application/json"},
            data=json.dumps(registration_data)
        )
        
        if response.status_code == 201 or response.status_code == 200:
            return response.json()
        else:
            print(f"Dynamic registration failed with status code: {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"Error during dynamic registration: {e}")
        return None

def perform_authorization_code_flow(auth_endpoint, token_endpoint, client_id, redirect_uri="http://localhost:8000/callback"):
    """Perform the OAuth 2.1 authorization code flow with PKCE"""
    # Generate PKCE code verifier and challenge
    code_verifier, code_challenge = generate_pkce_pair()
    
    # Start the callback server
    server = HTTPServer(('localhost', 8000), CallbackHandler)
    server.authorization_code = None
    
    # Build the authorization URL
    auth_url = (
        f"{auth_endpoint}?"
        f"client_id={client_id}&"
        f"response_type=code&"
        f"redirect_uri={redirect_uri}&"
        f"scope=mcp&"  # Assuming "mcp" scope, adjust as needed
        f"code_challenge={code_challenge}&"
        f"code_challenge_method=S256"
    )
    
    # Open the browser for user authentication
    print(f"Opening browser for authorization...")
    webbrowser.open(auth_url)
    
    # Wait for the callback with the authorization code
    print("Waiting for authorization callback...")
    server.handle_request()
    auth_code = server.authorization_code
    
    if not auth_code:
        print("Authorization failed. No code received.")
        return None
    
    # Exchange the authorization code for tokens
    token_data = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": code_verifier
    }
    
    try:
        token_response = requests.post(
            token_endpoint,
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        
        if token_response.status_code == 200:
            return token_response.json()
        else:
            print(f"Token exchange failed with status code: {token_response.status_code}")
            print(f"Error: {token_response.text}")
            return None
    except requests.RequestException as e:
        print(f"Error during token exchange: {e}")
        return None

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Authenticate with MCP SSE endpoint and output HTTP headers.')
    parser.add_argument('mcp_url', help='The MCP SSE endpoint URL')
    parser.add_argument('--client-id', help='Pre-registered OAuth client ID (if dynamic registration is not supported)')
    args = parser.parse_args()
    
    # Step 1: Discover authorization server metadata
    print(f"Discovering authorization server metadata for {args.mcp_url}...")
    metadata, auth_base_url = discover_auth_server_metadata(args.mcp_url)
    
    # Print discovered endpoints
    print(f"Authorization Endpoint: {metadata.get('authorization_endpoint')}")
    print(f"Token Endpoint: {metadata.get('token_endpoint')}")
    print(f"Registration Endpoint: {metadata.get('registration_endpoint', 'Not provided')}")
    
    # Step 2: Perform dynamic client registration if supported
    client_id = args.client_id
    if not client_id and 'registration_endpoint' in metadata:
        print("Performing dynamic client registration...")
        registration_result = perform_dynamic_registration(metadata['registration_endpoint'])
        if registration_result:
            client_id = registration_result.get('client_id')
            print(f"Successfully registered client with ID: {client_id}")
        else:
            print("Dynamic registration failed. Please provide a pre-registered client ID.")
            return
    
    # If we still don't have a client ID, fail
    if not client_id:
        print("No client ID available. Cannot continue authentication.")
        print("Please either:")
        print("1. Provide a pre-registered client ID using --client-id")
        print("2. Use an MCP server that supports dynamic client registration")
        return
    
    # Step 3: Perform authorization code flow with PKCE
    print(f"Starting OAuth authorization code flow...")
    token_result = perform_authorization_code_flow(
        metadata['authorization_endpoint'],
        metadata['token_endpoint'],
        client_id
    )
    
    if not token_result:
        print("Authentication failed. Could not obtain access token.")
        return
    
    # Extract the access token
    access_token = token_result.get('access_token')
    
    if not access_token:
        print("No access token received in the response.")
        return
    
    # Step 4: Output the HTTP headers
    print("\n===== HTTP HEADERS =====")
    print(f"Authorization: Bearer {access_token}")
    print("========================\n")
    print("Use these headers in your subsequent requests to the MCP SSE endpoint.")
    print(f"Example curl command:")
    print(f'curl -H "Authorization: Bearer {access_token}" {args.mcp_url}')

if __name__ == "__main__":
    main()