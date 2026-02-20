# networkprocedurecall

`networkprocedurecall` provides a certificate-authenticated network interface for
`@opsimathically/workerprocedurecall` using private-CA mTLS.

## Security Model

- Mutual TLS transport (`tls.createServer` / `tls.connect`)
- Private-CA trust (no public CA required)
- API-key authentication inside the mTLS channel
- Privilege-aware operations:
  - `invoke_functions`
  - `define_functions`
  - `undefine_functions`
  - `define_constants`
  - `undefine_constants`
  - `define_dependencies`
  - `undefine_dependencies`
  - `admin_privileges`
  - `all_privileges`

## Install

```bash
npm install
```

## Run Tests

```bash
npm test
```

## Minimal Usage (mTLS)

```typescript
import { WorkerProcedureCall } from '@opsimathically/workerprocedurecall';
import { NetworkProcedureCall, NetworkProcedureCallClient } from '@opsimathically/networkprocedurecall';

(async function () {
  const workerprocedurecall = new WorkerProcedureCall();

  await workerprocedurecall.defineWorkerFunction({
    name: 'WPCFunction2',
    worker_func: async function (): Promise<string> {
      return 'ok';
    }
  });

  await workerprocedurecall.startWorkers({ count: 2 });

  const server_key_pem = process.env.SERVER_KEY_PEM as string;
  const server_cert_pem = process.env.SERVER_CERT_PEM as string;
  const server_ca_pem = process.env.SERVER_CA_PEM as string;

  const client_key_pem = process.env.CLIENT_KEY_PEM as string;
  const client_cert_pem = process.env.CLIENT_CERT_PEM as string;
  const client_ca_pem = process.env.CLIENT_CA_PEM as string;

  const networkprocedurecall = new NetworkProcedureCall({ workerprocedurecall });

  await networkprocedurecall.start({
    information: { server_name: 'server_1' },
    network: { bind_addr: '127.0.0.1', tcp_listen_port: 6767 },
    tls_mtls: {
      key_pem: server_key_pem,
      cert_pem: server_cert_pem,
      ca_pem: server_ca_pem,
      min_version: 'TLSv1.3'
    },
    auth_callback: async function (params) {
      if (params.api_key === 'test_api_key_1') {
        return {
          state: 'authenticated',
          privileges: ['all_privileges']
        };
      }
      return 'failed';
    }
  });

  const networkprocedurecallclient = new NetworkProcedureCallClient({
    servers: {
      server_1: {
        network: { host: '127.0.0.1', tcp_remote_port: 6767 },
        tls_mtls: {
          key_pem: client_key_pem,
          cert_pem: client_cert_pem,
          ca_pem: client_ca_pem,
          servername: 'localhost',
          min_version: 'TLSv1.3'
        },
        authentication: { api_key: 'test_api_key_1' }
      }
    }
  });

  const function_return_value = await networkprocedurecallclient.server_1.call.WPCFunction2();
  console.log(function_return_value);
})();
```

## all_servers Aggregate Operations

`NetworkProcedureCallClient` reserves the member name `all_servers`. It runs an
operation against every configured server and returns a per-server result map.

```typescript
const define_result = await networkprocedurecallclient.all_servers.defineFunction({
  name: 'SomeFunctionDefinedOnAllServers',
  worker_func: async function (something: string): Promise<string> {
    return `hello: ${something}`;
  }
});

const invoke_result =
  await networkprocedurecallclient.all_servers.call.SomeFunctionDefinedOnAllServers('world');

console.log(define_result);
console.log(invoke_result);
```

Aggregate result shape:

```typescript
type all_servers_operation_result_t<result_t> =
  | { state: 'ok'; result: result_t }
  | { state: 'error'; error: { code: string; message: string; details?: unknown } };

type all_servers_operation_result_map_t<result_t> = Record<
  string,
  all_servers_operation_result_t<result_t>
>;
```

Notes:
- Single-server calls are unchanged (`networkprocedurecallclient.server_1.call.X()`).
- `all_servers` does not fail-fast; each server gets an `ok` or `error` entry.
- `servers` config cannot contain a key named `all_servers` (reserved).

## Abuse Controls (Rate Limiting + DoS Guards)

`NetworkProcedureCall.start(...)` accepts an optional `abuse_controls` block. If
omitted, safe defaults are applied automatically.

```typescript
await networkprocedurecall.start({
  information: { server_name: 'server_1' },
  network: { bind_addr: '127.0.0.1', tcp_listen_port: 6767 },
  tls_mtls: {
    key_pem: server_key_pem,
    cert_pem: server_cert_pem,
    ca_pem: server_ca_pem,
    min_version: 'TLSv1.3'
  },
  abuse_controls: {
    connection_controls: {
      max_concurrent_sockets: 1024,
      max_concurrent_handshakes: 256,
      max_unauthenticated_sessions: 256,
      global_connection_window_ms: 1000,
      global_max_new_connections_per_window: 512,
      per_ip_max_new_connections_per_window: 64,
      tls_handshake_timeout_ms: 5000,
      auth_message_timeout_ms: 5000,
      max_pre_auth_frame_bytes: 64 * 1024,
      max_post_auth_frame_bytes: 1024 * 1024
    },
    auth_controls: {
      pending_auth_window_ms: 10_000,
      max_pending_auth_attempts_per_ip_per_window: 100,
      failed_auth_window_ms: 60_000,
      max_failed_auth_per_ip_per_window: 20,
      max_failed_auth_per_api_key_per_window: 20,
      block_duration_ms: 60_000,
      enable_blocklist: true
    },
    request_controls: {
      max_in_flight_requests_per_connection: 128,
      per_connection: {
        enabled: true,
        tokens_per_interval: 200,
        interval_ms: 1000,
        burst_tokens: 400
      },
      per_api_key: {
        enabled: true,
        tokens_per_interval: 1000,
        interval_ms: 1000,
        burst_tokens: 2000
      },
      per_ip: {
        enabled: true,
        tokens_per_interval: 500,
        interval_ms: 1000,
        burst_tokens: 1000
      }
    }
  },
  auth_callback: async function (params) {
    if (params.api_key === 'test_api_key_1') {
      return { state: 'authenticated', privileges: ['all_privileges'] };
    }
    return 'failed';
  }
});
```

Behavior:
- Connection admission limits enforce global and per-IP new-connection windows.
- Pre-auth sockets are dropped on timeout if `auth` is not sent promptly.
- Requests are rate-limited per connection, per API key, and per IP.
- Failures use structured error codes including:
  - `rate_limited`
  - `connection_limited`
  - `handshake_limited`
  - `auth_throttled`

You can inspect counters via `networkprocedurecall.getAbuseMetrics()`.

Tuning guidance:
- Internet-facing deployments:
  - Keep lower `per_ip_max_new_connections_per_window`.
  - Keep `auth_message_timeout_ms` short (1-5s).
  - Keep per-key and per-IP request limiters enabled.
- Internal trusted networks:
  - You can raise burst limits and in-flight limits.
  - Keep pre-auth timeout and handshake caps enabled.
- Tradeoff:
  - Aggressive limits reduce abuse impact but can create false positives for
    bursty legitimate clients.

## Security Checklist

- Never disable certificate verification.
- Always set the client `servername` to match server certificate SAN/CN.
- Use short-lived certificates and rotate automatically.
- Rotate API keys independently from certificates.
- Bind API keys to cert identity (fingerprint/SAN) in `auth_callback` where possible.
- Restrict `define_function` to tightly trusted operators.

## Test Coverage

See:
- `test/networkprocedurecall/networkprocedurecall.tls_mtls.test.ts`
