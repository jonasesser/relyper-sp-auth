# @relyper/sp-auth

Service Provider SDK for integrating with **Relyper Identity Provider**.

This module allows external service providers to authenticate their users against Relyper's centralized identity provider. It handles OAuth 2.0 / OIDC flows and provides utilities for secure token management and session handling.

## Installation

```bash
npm install @relyper/sp-auth
```

## Quick Start

```typescript
import { ServiceProviderAuth } from '@relyper/sp-auth';

const auth = new ServiceProviderAuth({
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  redirectUri: 'https://your-app.com/callback'
});

const token = auth.authenticate();
```

## Development

```bash
npm run dev
```

## Build

```bash
npm run build
```

## Documentation

For detailed integration documentation, see [Relyper Documentation](https://docs.relyper.dev).

## License

MIT
