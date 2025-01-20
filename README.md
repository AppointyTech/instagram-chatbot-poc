# Instagram Chatbot Integration Guide

This guide explains how to build an Instagram chatbot that can automatically respond to messages using AI. Here's the step-by-step process:

## 1. Instagram Login & Authorization

1. Create a Meta Developer account and set up an Instagram app
2. Configure OAuth settings with:
   - Valid OAuth Redirect URI
   - Required permissions: `instagram_business_basic`, `instagram_business_manage_messages`
3. Implement login endpoint (`/connect`) that redirects to Instagram authorization URL
4. Handle OAuth callback (`/oauth/callback`) to:
   - Exchange authorization code for access token
   - Store token and user info in database

## 2. Token Storage

1. Create database table to store:
   - Instagram user ID
   - Access token 
   - Token expiration
   - User metadata
2. Implement token storage logic to:
   - Insert new tokens
   - Update existing tokens
   - Handle token expiration

## 3. Webhook Setup

1. Create webhook subscription in Meta Developer Portal:
   - Configure webhook URL (e.g. `https://your-domain.com/webhook`)
   - Select `messages` field
   - Set verify token for security
2. Implement webhook endpoint:
   - Handle verification requests (GET)
   - Process incoming message events (POST)

## 4. Message Processing Flow

1. Receive webhook payload containing:
   - Sender ID
   - Recipient ID 
   - Message content
2. Store message in database
3. Generate AI response for the message
4. Lookup recipient's access token using recipient ID
5. Send response back to sender using:
   - Instagram Graph API
   - Recipient's access token
   - Sender's ID as recipient

## Code Structure

The main components are:

- `handleConnect()` - Initiates Instagram authorization
- `handleOAuthCallback()` - Processes OAuth callback and stores tokens
- `handleWebhook()` - Webhook endpoint for receiving messages
- `handleMessage()` - Core message processing logic
- `sendInstagramMessage()` - Sends responses back to Instagram

## Environment Variables Required
- INSTAGRAM_CLIENT_ID
- INSTAGRAM_CLIENT_SECRET
- REDIRECT_URI
- APP_SECRET
- DATABASE_URL

