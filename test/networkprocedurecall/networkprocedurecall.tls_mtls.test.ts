import assert from 'node:assert';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import test from 'node:test';

import { WorkerProcedureCall } from '@opsimathically/workerprocedurecall';

import {
  NetworkProcedureCall,
  NetworkProcedureCallClient,
  type networkprocedurecall_abuse_controls_t,
  type privilege_name_t
} from '../../src';

type tls_material_t = {
  ca_cert_pem: string;
  server_key_pem: string;
  server_cert_pem: string;
  client_key_pem: string;
  client_cert_pem: string;
  bad_client_key_pem: string;
  bad_client_cert_pem: string;
  wrong_ca_cert_pem: string;
};

type mtls_fixture_params_t = {
  tls_material: tls_material_t;
  client_key_pem: string;
  client_cert_pem: string;
  client_ca_pem: string;
  client_servername: string;
  api_key: string;
  auth_map: Record<string, privilege_name_t[] | null>;
  request_timeout_ms?: number;
  abuse_controls?: networkprocedurecall_abuse_controls_t;
};

type mtls_fixture_t = {
  workerprocedurecall: WorkerProcedureCall;
  networkprocedurecall: NetworkProcedureCall;
  networkprocedurecallclient: NetworkProcedureCallClient;
  tcp_listen_port: number;
  cleanup: () => Promise<void>;
};

type mtls_server_instance_t = {
  workerprocedurecall: WorkerProcedureCall;
  networkprocedurecall: NetworkProcedureCall;
  tcp_listen_port: number;
};

type mtls_dual_server_fixture_params_t = {
  tls_material: tls_material_t;
  server_1_client_api_key: string;
  server_2_client_api_key: string;
  server_1_auth_map: Record<string, privilege_name_t[] | null>;
  server_2_auth_map: Record<string, privilege_name_t[] | null>;
  request_timeout_ms?: number;
};

type mtls_dual_server_fixture_t = {
  server_1: mtls_server_instance_t;
  server_2: mtls_server_instance_t;
  networkprocedurecallclient: NetworkProcedureCallClient;
  cleanup: () => Promise<void>;
};

function RunCommand(params: { cmd: string; args: string[]; cwd: string }): void {
  execFileSync(params.cmd, params.args, {
    cwd: params.cwd,
    stdio: 'ignore'
  });
}

function ReadTextFile(params: { file_path: string }): string {
  return fs.readFileSync(params.file_path, 'utf8');
}

function WriteTextFile(params: { file_path: string; content: string }): void {
  fs.writeFileSync(params.file_path, params.content, 'utf8');
}

function GenerateTlsMaterial(): tls_material_t {
  const temp_dir = fs.mkdtempSync(path.join(os.tmpdir(), 'npc-mtls-test-'));

  const ca_key_path = path.join(temp_dir, 'ca.key.pem');
  const ca_cert_path = path.join(temp_dir, 'ca.cert.pem');

  RunCommand({
    cmd: 'openssl',
    args: [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-sha256',
      '-nodes',
      '-keyout',
      ca_key_path,
      '-out',
      ca_cert_path,
      '-days',
      '2',
      '-subj',
      '/CN=NPC Test Root CA'
    ],
    cwd: temp_dir
  });

  const server_key_path = path.join(temp_dir, 'server.key.pem');
  const server_csr_path = path.join(temp_dir, 'server.csr.pem');
  const server_cert_path = path.join(temp_dir, 'server.cert.pem');
  const server_ext_path = path.join(temp_dir, 'server.ext');

  WriteTextFile({
    file_path: server_ext_path,
    content: [
      'subjectAltName=DNS:localhost,IP:127.0.0.1',
      'extendedKeyUsage=serverAuth',
      'keyUsage=digitalSignature,keyEncipherment'
    ].join('\n')
  });

  RunCommand({
    cmd: 'openssl',
    args: [
      'req',
      '-new',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      server_key_path,
      '-out',
      server_csr_path,
      '-subj',
      '/CN=localhost'
    ],
    cwd: temp_dir
  });

  RunCommand({
    cmd: 'openssl',
    args: [
      'x509',
      '-req',
      '-in',
      server_csr_path,
      '-CA',
      ca_cert_path,
      '-CAkey',
      ca_key_path,
      '-CAcreateserial',
      '-out',
      server_cert_path,
      '-days',
      '2',
      '-sha256',
      '-extfile',
      server_ext_path
    ],
    cwd: temp_dir
  });

  const client_key_path = path.join(temp_dir, 'client.key.pem');
  const client_csr_path = path.join(temp_dir, 'client.csr.pem');
  const client_cert_path = path.join(temp_dir, 'client.cert.pem');
  const client_ext_path = path.join(temp_dir, 'client.ext');

  WriteTextFile({
    file_path: client_ext_path,
    content: [
      'extendedKeyUsage=clientAuth',
      'keyUsage=digitalSignature,keyEncipherment',
      'subjectAltName=URI:spiffe://npc/test-client'
    ].join('\n')
  });

  RunCommand({
    cmd: 'openssl',
    args: [
      'req',
      '-new',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      client_key_path,
      '-out',
      client_csr_path,
      '-subj',
      '/CN=npc-test-client'
    ],
    cwd: temp_dir
  });

  RunCommand({
    cmd: 'openssl',
    args: [
      'x509',
      '-req',
      '-in',
      client_csr_path,
      '-CA',
      ca_cert_path,
      '-CAkey',
      ca_key_path,
      '-CAcreateserial',
      '-out',
      client_cert_path,
      '-days',
      '2',
      '-sha256',
      '-extfile',
      client_ext_path
    ],
    cwd: temp_dir
  });

  const bad_ca_key_path = path.join(temp_dir, 'bad_ca.key.pem');
  const bad_ca_cert_path = path.join(temp_dir, 'bad_ca.cert.pem');

  RunCommand({
    cmd: 'openssl',
    args: [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-sha256',
      '-nodes',
      '-keyout',
      bad_ca_key_path,
      '-out',
      bad_ca_cert_path,
      '-days',
      '2',
      '-subj',
      '/CN=NPC Wrong Root CA'
    ],
    cwd: temp_dir
  });

  const bad_client_key_path = path.join(temp_dir, 'bad_client.key.pem');
  const bad_client_csr_path = path.join(temp_dir, 'bad_client.csr.pem');
  const bad_client_cert_path = path.join(temp_dir, 'bad_client.cert.pem');
  const bad_client_ext_path = path.join(temp_dir, 'bad_client.ext');

  WriteTextFile({
    file_path: bad_client_ext_path,
    content: [
      'extendedKeyUsage=clientAuth',
      'keyUsage=digitalSignature,keyEncipherment',
      'subjectAltName=URI:spiffe://npc/bad-client'
    ].join('\n')
  });

  RunCommand({
    cmd: 'openssl',
    args: [
      'req',
      '-new',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      bad_client_key_path,
      '-out',
      bad_client_csr_path,
      '-subj',
      '/CN=npc-bad-client'
    ],
    cwd: temp_dir
  });

  RunCommand({
    cmd: 'openssl',
    args: [
      'x509',
      '-req',
      '-in',
      bad_client_csr_path,
      '-CA',
      bad_ca_cert_path,
      '-CAkey',
      bad_ca_key_path,
      '-CAcreateserial',
      '-out',
      bad_client_cert_path,
      '-days',
      '2',
      '-sha256',
      '-extfile',
      bad_client_ext_path
    ],
    cwd: temp_dir
  });

  process.on('exit', () => {
    try {
      fs.rmSync(temp_dir, { recursive: true, force: true });
    } catch {
      // no-op cleanup path
    }
  });

  return {
    ca_cert_pem: ReadTextFile({ file_path: ca_cert_path }),
    server_key_pem: ReadTextFile({ file_path: server_key_path }),
    server_cert_pem: ReadTextFile({ file_path: server_cert_path }),
    client_key_pem: ReadTextFile({ file_path: client_key_path }),
    client_cert_pem: ReadTextFile({ file_path: client_cert_path }),
    bad_client_key_pem: ReadTextFile({ file_path: bad_client_key_path }),
    bad_client_cert_pem: ReadTextFile({ file_path: bad_client_cert_path }),
    wrong_ca_cert_pem: ReadTextFile({ file_path: bad_ca_cert_path })
  };
}

async function GetFreeTcpPort(): Promise<number> {
  const probe_server = net.createServer();

  const tcp_port = await new Promise<number>((resolve, reject) => {
    probe_server.once('error', (error) => {
      reject(error);
    });

    probe_server.listen(0, '127.0.0.1', () => {
      const address_information = probe_server.address();
      if (!address_information || typeof address_information === 'string') {
        reject(new Error('Failed to determine free tcp port.'));
        return;
      }

      resolve(address_information.port);
    });
  });

  await new Promise<void>((resolve, reject) => {
    probe_server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });

  return tcp_port;
}

async function Sleep(params: { duration_ms: number }): Promise<void> {
  await new Promise((resolve) => {
    setTimeout(resolve, params.duration_ms);
  });
}

function GetErrorCode(params: { error: unknown }): string | undefined {
  const error_value = params.error as { code?: unknown };
  return typeof error_value.code === 'string' ? error_value.code : undefined;
}

function GetErrorDetails(params: { error: unknown }): Record<string, unknown> | undefined {
  const error_value = params.error as { details?: unknown };
  if (!error_value.details || typeof error_value.details !== 'object') {
    return undefined;
  }
  return error_value.details as Record<string, unknown>;
}

async function BuildMtlsFixture(params: mtls_fixture_params_t): Promise<mtls_fixture_t> {
  const workerprocedurecall = new WorkerProcedureCall({
    call_timeout_ms: 10_000,
    control_timeout_ms: 10_000,
    restart_on_failure: true,
    max_restarts_per_worker: 2,
    max_pending_calls_per_worker: 1_000,
    restart_base_delay_ms: 50,
    restart_max_delay_ms: 1_000,
    restart_jitter_ms: 50
  });

  await workerprocedurecall.defineWorkerFunction({
    name: 'WPCFunction2',
    worker_func: async function (): Promise<string> {
      return 'wpc_function_2_result';
    }
  });

  await workerprocedurecall.defineWorkerFunction({
    name: 'DoubleValue',
    worker_func: async function (value: number): Promise<number> {
      return value * 2;
    }
  });

  await workerprocedurecall.defineWorkerFunction({
    name: 'SleepFunction',
    worker_func: async function (sleep_ms: number): Promise<string> {
      await new Promise((resolve) => {
        setTimeout(resolve, sleep_ms);
      });
      return `slept_${sleep_ms}`;
    }
  });

  await workerprocedurecall.startWorkers({ count: 2 });

  const tcp_listen_port = await GetFreeTcpPort();

  const networkprocedurecall = new NetworkProcedureCall({
    workerprocedurecall
  });

  await networkprocedurecall.start({
    information: {
      server_name: 'server_1'
    },
    network: {
      bind_addr: '127.0.0.1',
      tcp_listen_port
    },
    tls_mtls: {
      key_pem: params.tls_material.server_key_pem,
      cert_pem: params.tls_material.server_cert_pem,
      ca_pem: params.tls_material.ca_cert_pem,
      min_version: 'TLSv1.3',
      handshake_timeout_ms: 5_000,
      request_timeout_ms: params.request_timeout_ms ?? 2_000,
      max_frame_bytes: 1_048_576
    },
    abuse_controls: params.abuse_controls,
    auth_callback: async ({ api_key, tls_peer_fingerprint256 }) => {
      const privileges = params.auth_map[api_key] ?? null;
      if (!privileges) {
        return 'failed';
      }

      if (!tls_peer_fingerprint256 || tls_peer_fingerprint256.length === 0) {
        return 'failed';
      }

      return {
        state: 'authenticated',
        privileges
      };
    }
  });

  const networkprocedurecallclient = new NetworkProcedureCallClient({
    servers: {
      server_1: {
        network: {
          host: '127.0.0.1',
          tcp_remote_port: tcp_listen_port
        },
        tls_mtls: {
          key_pem: params.client_key_pem,
          cert_pem: params.client_cert_pem,
          ca_pem: params.client_ca_pem,
          servername: params.client_servername,
          min_version: 'TLSv1.3',
          handshake_timeout_ms: 5_000,
          request_timeout_ms: params.request_timeout_ms ?? 2_000,
          max_frame_bytes: 1_048_576
        },
        authentication: {
          api_key: params.api_key
        }
      }
    }
  });

  const cleanup = async (): Promise<void> => {
    await networkprocedurecallclient.disconnectAll();
    await networkprocedurecall.stop();
    await workerprocedurecall.stopWorkers();
  };

  return {
    workerprocedurecall,
    networkprocedurecall,
    networkprocedurecallclient,
    tcp_listen_port,
    cleanup
  };
}

async function BuildMtlsServerInstance(params: {
  server_name: string;
  tls_material: tls_material_t;
  auth_map: Record<string, privilege_name_t[] | null>;
  request_timeout_ms?: number;
}): Promise<mtls_server_instance_t> {
  const workerprocedurecall = new WorkerProcedureCall({
    call_timeout_ms: 10_000,
    control_timeout_ms: 10_000,
    restart_on_failure: true,
    max_restarts_per_worker: 2,
    max_pending_calls_per_worker: 1_000,
    restart_base_delay_ms: 50,
    restart_max_delay_ms: 1_000,
    restart_jitter_ms: 50
  });

  await workerprocedurecall.defineWorkerFunction({
    name: 'WPCFunction2',
    worker_func: async function (): Promise<string> {
      return 'wpc_function_2_result';
    }
  });

  await workerprocedurecall.startWorkers({ count: 2 });

  const tcp_listen_port = await GetFreeTcpPort();

  const networkprocedurecall = new NetworkProcedureCall({
    workerprocedurecall
  });

  await networkprocedurecall.start({
    information: {
      server_name: params.server_name
    },
    network: {
      bind_addr: '127.0.0.1',
      tcp_listen_port
    },
    tls_mtls: {
      key_pem: params.tls_material.server_key_pem,
      cert_pem: params.tls_material.server_cert_pem,
      ca_pem: params.tls_material.ca_cert_pem,
      min_version: 'TLSv1.3',
      handshake_timeout_ms: 5_000,
      request_timeout_ms: params.request_timeout_ms ?? 2_000,
      max_frame_bytes: 1_048_576
    },
    auth_callback: async ({ api_key, tls_peer_fingerprint256 }) => {
      const privileges = params.auth_map[api_key] ?? null;
      if (!privileges) {
        return 'failed';
      }

      if (!tls_peer_fingerprint256 || tls_peer_fingerprint256.length === 0) {
        return 'failed';
      }

      return {
        state: 'authenticated',
        privileges
      };
    }
  });

  return {
    workerprocedurecall,
    networkprocedurecall,
    tcp_listen_port
  };
}

async function BuildMtlsDualServerFixture(
  params: mtls_dual_server_fixture_params_t
): Promise<mtls_dual_server_fixture_t> {
  const server_1 = await BuildMtlsServerInstance({
    server_name: 'server_1',
    tls_material: params.tls_material,
    auth_map: params.server_1_auth_map,
    request_timeout_ms: params.request_timeout_ms
  });

  const server_2 = await BuildMtlsServerInstance({
    server_name: 'server_2',
    tls_material: params.tls_material,
    auth_map: params.server_2_auth_map,
    request_timeout_ms: params.request_timeout_ms
  });

  const networkprocedurecallclient = new NetworkProcedureCallClient({
    servers: {
      server_1: {
        network: {
          host: '127.0.0.1',
          tcp_remote_port: server_1.tcp_listen_port
        },
        tls_mtls: {
          key_pem: params.tls_material.client_key_pem,
          cert_pem: params.tls_material.client_cert_pem,
          ca_pem: params.tls_material.ca_cert_pem,
          servername: 'localhost',
          min_version: 'TLSv1.3',
          handshake_timeout_ms: 5_000,
          request_timeout_ms: params.request_timeout_ms ?? 2_000,
          max_frame_bytes: 1_048_576
        },
        authentication: {
          api_key: params.server_1_client_api_key
        }
      },
      server_2: {
        network: {
          host: '127.0.0.1',
          tcp_remote_port: server_2.tcp_listen_port
        },
        tls_mtls: {
          key_pem: params.tls_material.client_key_pem,
          cert_pem: params.tls_material.client_cert_pem,
          ca_pem: params.tls_material.ca_cert_pem,
          servername: 'localhost',
          min_version: 'TLSv1.3',
          handshake_timeout_ms: 5_000,
          request_timeout_ms: params.request_timeout_ms ?? 2_000,
          max_frame_bytes: 1_048_576
        },
        authentication: {
          api_key: params.server_2_client_api_key
        }
      }
    }
  });

  const cleanup = async (): Promise<void> => {
    await networkprocedurecallclient.disconnectAll();
    await server_1.networkprocedurecall.stop();
    await server_2.networkprocedurecall.stop();
    await server_1.workerprocedurecall.stopWorkers();
    await server_2.workerprocedurecall.stopWorkers();
  };

  return {
    server_1,
    server_2,
    networkprocedurecallclient,
    cleanup
  };
}

const tls_material = GenerateTlsMaterial();

test('mTLS success path: valid certs and valid API key invoke remote function.', async () => {
  const fixture = await BuildMtlsFixture({
    tls_material,
    client_key_pem: tls_material.client_key_pem,
    client_cert_pem: tls_material.client_cert_pem,
    client_ca_pem: tls_material.ca_cert_pem,
    client_servername: 'localhost',
    api_key: 'valid_api_key',
    auth_map: {
      valid_api_key: ['all_privileges']
    }
  });

  try {
    const function_return_value = await (fixture.networkprocedurecallclient as any).server_1.call.WPCFunction2();
    assert.equal(function_return_value, 'wpc_function_2_result');

    const abuse_metrics = fixture.networkprocedurecall.getAbuseMetrics();
    assert.equal(abuse_metrics.active_handshake_count, 0);
    assert.equal(abuse_metrics.active_unauthenticated_session_count, 0);
  } finally {
    await fixture.cleanup();
  }
});

test('mTLS client cert rejection: untrusted client cert fails handshake.', async () => {
  const fixture = await BuildMtlsFixture({
    tls_material,
    client_key_pem: tls_material.bad_client_key_pem,
    client_cert_pem: tls_material.bad_client_cert_pem,
    client_ca_pem: tls_material.ca_cert_pem,
    client_servername: 'localhost',
    api_key: 'valid_api_key',
    auth_map: {
      valid_api_key: ['all_privileges']
    }
  });

  try {
    await assert.rejects(async () => {
      await (fixture.networkprocedurecallclient as any).server_1.call.WPCFunction2();
    });
  } finally {
    await fixture.cleanup();
  }
});

test('mTLS server cert validation: wrong trusted CA fails client validation.', async () => {
  const fixture = await BuildMtlsFixture({
    tls_material,
    client_key_pem: tls_material.client_key_pem,
    client_cert_pem: tls_material.client_cert_pem,
    client_ca_pem: tls_material.wrong_ca_cert_pem,
    client_servername: 'localhost',
    api_key: 'valid_api_key',
    auth_map: {
      valid_api_key: ['all_privileges']
    }
  });

  try {
    await assert.rejects(async () => {
      await (fixture.networkprocedurecallclient as any).server_1.call.WPCFunction2();
    });
  } finally {
    await fixture.cleanup();
  }
});

test('mTLS servername validation: wrong servername fails handshake.', async () => {
  const fixture = await BuildMtlsFixture({
    tls_material,
    client_key_pem: tls_material.client_key_pem,
    client_cert_pem: tls_material.client_cert_pem,
    client_ca_pem: tls_material.ca_cert_pem,
    client_servername: 'wrong-host-name.example',
    api_key: 'valid_api_key',
    auth_map: {
      valid_api_key: ['all_privileges']
    }
  });

  try {
    await assert.rejects(async () => {
      await (fixture.networkprocedurecallclient as any).server_1.call.WPCFunction2();
    });
  } finally {
    await fixture.cleanup();
  }
});

test('mTLS API key rejection: cert handshake succeeds but API key auth fails.', async () => {
  const fixture = await BuildMtlsFixture({
    tls_material,
    client_key_pem: tls_material.client_key_pem,
    client_cert_pem: tls_material.client_cert_pem,
    client_ca_pem: tls_material.ca_cert_pem,
    client_servername: 'localhost',
    api_key: 'invalid_api_key',
    auth_map: {
      valid_api_key: ['all_privileges']
    }
  });

  try {
    await assert.rejects(async () => {
      await (fixture.networkprocedurecallclient as any).server_1.call.WPCFunction2();
    });
  } finally {
    await fixture.cleanup();
  }
});

test('mTLS privilege enforcement: invoke allowed but define_constant denied.', async () => {
  const fixture = await BuildMtlsFixture({
    tls_material,
    client_key_pem: tls_material.client_key_pem,
    client_cert_pem: tls_material.client_cert_pem,
    client_ca_pem: tls_material.ca_cert_pem,
    client_servername: 'localhost',
    api_key: 'invoke_only_key',
    auth_map: {
      invoke_only_key: ['invoke_functions']
    }
  });

  try {
    const function_return_value = await (fixture.networkprocedurecallclient as any).server_1.call.WPCFunction2();
    assert.equal(function_return_value, 'wpc_function_2_result');

    await assert.rejects(
      async () => {
        await (fixture.networkprocedurecallclient as any).server_1.defineConstant({
          name: 'REMOTE_TEST_CONSTANT',
          value: 'hello'
        });
      },
      (error: unknown) => {
        const message = error instanceof Error ? error.message : String(error);
        return message.includes('requires privilege');
      }
    );

    await assert.rejects(
      async () => {
        await (fixture.networkprocedurecallclient as any).server_1.defineDependency({
          alias: 'path_dep',
          module_specifier: 'node:path'
        });
      },
      (error: unknown) => {
        const message = error instanceof Error ? error.message : String(error);
        return message.includes('requires privilege');
      }
    );
  } finally {
    await fixture.cleanup();
  }
});

test(
  'mTLS remote dependency/constant/function lifecycle works over networkprocedurecall client.',
  async () => {
    const fixture = await BuildMtlsFixture({
      tls_material,
      client_key_pem: tls_material.client_key_pem,
      client_cert_pem: tls_material.client_cert_pem,
      client_ca_pem: tls_material.ca_cert_pem,
      client_servername: 'localhost',
      api_key: 'valid_api_key',
      auth_map: {
        valid_api_key: ['all_privileges']
      }
    });

    try {
      await (fixture.networkprocedurecallclient as any).server_1.defineDependency({
        alias: 'path_dep',
        module_specifier: 'node:path'
      });

      await (fixture.networkprocedurecallclient as any).server_1.defineConstant({
        name: 'SERVICE_PREFIX',
        value: 'api-v1'
      });

      await (fixture.networkprocedurecallclient as any).server_1.defineFunction({
        name: 'RemotePathBasename',
        worker_func: async function (file_path: string): Promise<string> {
          const path_module = (await wpc_import('path_dep')) as {
            basename: (value: string) => string;
          };
          const prefix = wpc_constant('SERVICE_PREFIX') as string;
          return `${prefix}:${path_module.basename(file_path)}`;
        }
      });

      const lifecycle_result = await (fixture.networkprocedurecallclient as any).server_1.call.RemotePathBasename(
        '/tmp/test_dir/example.txt'
      );
      assert.equal(lifecycle_result, 'api-v1:example.txt');

      await (fixture.networkprocedurecallclient as any).server_1.undefineFunction({
        name: 'RemotePathBasename'
      });
      await (fixture.networkprocedurecallclient as any).server_1.undefineConstant({
        name: 'SERVICE_PREFIX'
      });
      await (fixture.networkprocedurecallclient as any).server_1.undefineDependency({
        alias: 'path_dep'
      });

      await assert.rejects(async () => {
        await (fixture.networkprocedurecallclient as any).server_1.call.RemotePathBasename(
          '/tmp/test_dir/example.txt'
        );
      });
    } finally {
      await fixture.cleanup();
    }
  }
);

test('mTLS concurrent invocations resolve successfully.', async () => {
  const fixture = await BuildMtlsFixture({
    tls_material,
    client_key_pem: tls_material.client_key_pem,
    client_cert_pem: tls_material.client_cert_pem,
    client_ca_pem: tls_material.ca_cert_pem,
    client_servername: 'localhost',
    api_key: 'valid_api_key',
    auth_map: {
      valid_api_key: ['all_privileges']
    },
    request_timeout_ms: 5_000
  });

  try {
    const invocation_promises: Promise<unknown>[] = [];

    for (let index = 0; index < 20; index += 1) {
      invocation_promises.push(
        (fixture.networkprocedurecallclient as any).server_1.call.DoubleValue(index)
      );
    }

    const invocation_results = await Promise.all(invocation_promises);

    for (let index = 0; index < 20; index += 1) {
      assert.equal(invocation_results[index], index * 2);
    }
  } finally {
    await fixture.cleanup();
  }
});

test('mTLS in-flight call rejects when server connection is interrupted.', async () => {
  const fixture = await BuildMtlsFixture({
    tls_material,
    client_key_pem: tls_material.client_key_pem,
    client_cert_pem: tls_material.client_cert_pem,
    client_ca_pem: tls_material.ca_cert_pem,
    client_servername: 'localhost',
    api_key: 'valid_api_key',
    auth_map: {
      valid_api_key: ['all_privileges']
    },
    request_timeout_ms: 5_000
  });

  try {
    const in_flight_call_promise = (fixture.networkprocedurecallclient as any).server_1.call.SleepFunction(3_000);

    await new Promise((resolve) => {
      setTimeout(resolve, 150);
    });

    await fixture.networkprocedurecall.stop();

    await assert.rejects(async () => {
      await in_flight_call_promise;
    });
  } finally {
    await fixture.cleanup();
  }
});

test('handshake DoS control: exceeding max_concurrent_handshakes rejects additional raw connections.', async () => {
  const fixture = await BuildMtlsFixture({
    tls_material,
    client_key_pem: tls_material.client_key_pem,
    client_cert_pem: tls_material.client_cert_pem,
    client_ca_pem: tls_material.ca_cert_pem,
    client_servername: 'localhost',
    api_key: 'valid_api_key',
    auth_map: {
      valid_api_key: ['all_privileges']
    },
    abuse_controls: {
      connection_controls: {
        max_concurrent_handshakes: 1,
        tls_handshake_timeout_ms: 2_000
      }
    }
  });

  const first_raw_socket = net.createConnection({
    host: '127.0.0.1',
    port: fixture.tcp_listen_port
  });

  await new Promise<void>((resolve, reject) => {
    first_raw_socket.once('connect', () => resolve());
    first_raw_socket.once('error', (error) => reject(error));
  });

  const second_raw_socket = net.createConnection({
    host: '127.0.0.1',
    port: fixture.tcp_listen_port
  });

  try {
    await new Promise<void>((resolve, reject) => {
      let resolved = false;

      const finish = (): void => {
        if (resolved) {
          return;
        }
        resolved = true;
        resolve();
      };

      second_raw_socket.once('close', () => finish());
      second_raw_socket.once('error', () => finish());

      setTimeout(() => {
        if (resolved) {
          return;
        }
        reject(new Error('Expected second raw connection to be rejected quickly.'));
      }, 1_000);
    });

    const abuse_metrics = fixture.networkprocedurecall.getAbuseMetrics();
    assert.ok(abuse_metrics.handshake_limited_count >= 1);
    assert.ok(abuse_metrics.connection_rejected_count >= 1);
  } finally {
    first_raw_socket.destroy();
    second_raw_socket.destroy();
    await fixture.cleanup();
  }
});

test('connection window DoS control: per-IP new connection window is enforced.', async () => {
  const fixture = await BuildMtlsFixture({
    tls_material,
    client_key_pem: tls_material.client_key_pem,
    client_cert_pem: tls_material.client_cert_pem,
    client_ca_pem: tls_material.ca_cert_pem,
    client_servername: 'localhost',
    api_key: 'valid_api_key',
    auth_map: {
      valid_api_key: ['all_privileges']
    },
    abuse_controls: {
      connection_controls: {
        global_connection_window_ms: 5_000,
        global_max_new_connections_per_window: 1,
        per_ip_max_new_connections_per_window: 1
      }
    }
  });

  try {
    await (fixture.networkprocedurecallclient as any).server_1.call.WPCFunction2();
    await fixture.networkprocedurecallclient.disconnectAll();

    await assert.rejects(async () => {
      await (fixture.networkprocedurecallclient as any).server_1.call.WPCFunction2();
    });

    const abuse_metrics = fixture.networkprocedurecall.getAbuseMetrics();
    assert.ok(abuse_metrics.connection_rejected_count >= 1);
  } finally {
    await fixture.cleanup();
  }
});

test('pre-auth timeout: authenticated TLS peer is disconnected when auth message is not sent in time.', async () => {
  const fixture = await BuildMtlsFixture({
    tls_material,
    client_key_pem: tls_material.client_key_pem,
    client_cert_pem: tls_material.client_cert_pem,
    client_ca_pem: tls_material.ca_cert_pem,
    client_servername: 'localhost',
    api_key: 'valid_api_key',
    auth_map: {
      valid_api_key: ['all_privileges']
    },
    abuse_controls: {
      connection_controls: {
        auth_message_timeout_ms: 150
      }
    }
  });

  const tls_socket = tls.connect({
    host: '127.0.0.1',
    port: fixture.tcp_listen_port,
    key: tls_material.client_key_pem,
    cert: tls_material.client_cert_pem,
    ca: tls_material.ca_cert_pem,
    servername: 'localhost',
    minVersion: 'TLSv1.3',
    rejectUnauthorized: true
  });

  try {
    await new Promise<void>((resolve, reject) => {
      tls_socket.once('secureConnect', () => resolve());
      tls_socket.once('error', (error) => reject(error));
    });

    await new Promise<void>((resolve, reject) => {
      let resolved = false;
      const finish = (): void => {
        if (resolved) {
          return;
        }
        resolved = true;
        resolve();
      };

      tls_socket.once('close', () => finish());
      tls_socket.once('error', () => finish());

      setTimeout(() => {
        if (!resolved) {
          reject(new Error('Expected pre-auth timeout disconnect.'));
        }
      }, 2_000);
    });
  } finally {
    tls_socket.destroy();
    await fixture.cleanup();
  }
});

test('rate limiting: per-connection burst limit returns rate_limited.', async () => {
  const fixture = await BuildMtlsFixture({
    tls_material,
    client_key_pem: tls_material.client_key_pem,
    client_cert_pem: tls_material.client_cert_pem,
    client_ca_pem: tls_material.ca_cert_pem,
    client_servername: 'localhost',
    api_key: 'valid_api_key',
    auth_map: {
      valid_api_key: ['all_privileges']
    },
    abuse_controls: {
      request_controls: {
        per_connection: {
          enabled: true,
          tokens_per_interval: 1,
          interval_ms: 5_000,
          burst_tokens: 1
        },
        per_api_key: {
          enabled: false
        },
        per_ip: {
          enabled: false
        }
      }
    }
  });

  try {
    await (fixture.networkprocedurecallclient as any).server_1.call.WPCFunction2();

    await assert.rejects(
      async () => {
        await (fixture.networkprocedurecallclient as any).server_1.call.WPCFunction2();
      },
      (error: unknown) => {
        return GetErrorCode({ error }) === 'rate_limited';
      }
    );
  } finally {
    await fixture.cleanup();
  }
});

test('rate limiting: per-api-key limiter is shared across clients.', async () => {
  const fixture = await BuildMtlsFixture({
    tls_material,
    client_key_pem: tls_material.client_key_pem,
    client_cert_pem: tls_material.client_cert_pem,
    client_ca_pem: tls_material.ca_cert_pem,
    client_servername: 'localhost',
    api_key: 'shared_api_key',
    auth_map: {
      shared_api_key: ['all_privileges']
    },
    abuse_controls: {
      request_controls: {
        per_connection: {
          enabled: false
        },
        per_api_key: {
          enabled: true,
          tokens_per_interval: 1,
          interval_ms: 5_000,
          burst_tokens: 1
        },
        per_ip: {
          enabled: false
        }
      }
    }
  });

  const second_client = new NetworkProcedureCallClient({
    servers: {
      server_1: {
        network: {
          host: '127.0.0.1',
          tcp_remote_port: fixture.tcp_listen_port
        },
        tls_mtls: {
          key_pem: tls_material.client_key_pem,
          cert_pem: tls_material.client_cert_pem,
          ca_pem: tls_material.ca_cert_pem,
          servername: 'localhost',
          min_version: 'TLSv1.3',
          request_timeout_ms: 2_000,
          handshake_timeout_ms: 5_000,
          max_frame_bytes: 1_048_576
        },
        authentication: {
          api_key: 'shared_api_key'
        }
      }
    }
  });

  try {
    await (fixture.networkprocedurecallclient as any).server_1.call.WPCFunction2();
    await assert.rejects(
      async () => {
        await (second_client as any).server_1.call.WPCFunction2();
      },
      (error: unknown) => {
        const details = GetErrorDetails({ error });
        return (
          GetErrorCode({ error }) === 'rate_limited' &&
          details?.scope === 'per_api_key'
        );
      }
    );
  } finally {
    await second_client.disconnectAll();
    await fixture.cleanup();
  }
});

test('auth throttling: repeated failed auth attempts trigger auth_throttled.', async () => {
  const fixture = await BuildMtlsFixture({
    tls_material,
    client_key_pem: tls_material.client_key_pem,
    client_cert_pem: tls_material.client_cert_pem,
    client_ca_pem: tls_material.ca_cert_pem,
    client_servername: 'localhost',
    api_key: 'bad_api_key',
    auth_map: {
      valid_api_key: ['all_privileges']
    },
    abuse_controls: {
      auth_controls: {
        failed_auth_window_ms: 5_000,
        max_failed_auth_per_ip_per_window: 1,
        max_failed_auth_per_api_key_per_window: 1,
        block_duration_ms: 1_000,
        enable_blocklist: true
      }
    }
  });

  try {
    await assert.rejects(async () => {
      await (fixture.networkprocedurecallclient as any).server_1.call.WPCFunction2();
    });

    await assert.rejects(
      async () => {
        await (fixture.networkprocedurecallclient as any).server_1.call.WPCFunction2();
      },
      (error: unknown) => {
        if (GetErrorCode({ error }) === 'auth_throttled') {
          return true;
        }

        const message = error instanceof Error ? error.message : String(error);
        return message.includes('Socket closed before mTLS secureConnect completed.');
      }
    );

    const abuse_metrics = fixture.networkprocedurecall.getAbuseMetrics();
    assert.ok(abuse_metrics.auth_throttled_count >= 1);
  } finally {
    await fixture.cleanup();
  }
});

test('rate limiter reset: requests succeed again after limiter interval elapses.', async () => {
  const fixture = await BuildMtlsFixture({
    tls_material,
    client_key_pem: tls_material.client_key_pem,
    client_cert_pem: tls_material.client_cert_pem,
    client_ca_pem: tls_material.ca_cert_pem,
    client_servername: 'localhost',
    api_key: 'valid_api_key',
    auth_map: {
      valid_api_key: ['all_privileges']
    },
    abuse_controls: {
      request_controls: {
        per_connection: {
          enabled: true,
          tokens_per_interval: 1,
          interval_ms: 150,
          burst_tokens: 1
        },
        per_api_key: {
          enabled: false
        },
        per_ip: {
          enabled: false
        }
      }
    }
  });

  try {
    await (fixture.networkprocedurecallclient as any).server_1.call.WPCFunction2();
    await assert.rejects(async () => {
      await (fixture.networkprocedurecallclient as any).server_1.call.WPCFunction2();
    });

    await Sleep({ duration_ms: 220 });
    const second_success = await (fixture.networkprocedurecallclient as any).server_1.call.WPCFunction2();
    assert.equal(second_success, 'wpc_function_2_result');
  } finally {
    await fixture.cleanup();
  }
});

test('all_servers defineFunction and invoke succeeds across two servers.', async () => {
  const fixture = await BuildMtlsDualServerFixture({
    tls_material,
    server_1_client_api_key: 'valid_api_key',
    server_2_client_api_key: 'valid_api_key',
    server_1_auth_map: {
      valid_api_key: ['all_privileges']
    },
    server_2_auth_map: {
      valid_api_key: ['all_privileges']
    }
  });

  try {
    const define_result = await fixture.networkprocedurecallclient.all_servers.defineFunction({
      name: 'SomeFunctionDefinedOnAllServers',
      worker_func: async function (something: unknown): Promise<string> {
        return `hello: ${String(something)}`;
      }
    });
    assert.equal(define_result.server_1.state, 'ok');
    assert.equal(define_result.server_2.state, 'ok');

    const invoke_result =
      await fixture.networkprocedurecallclient.all_servers.call.SomeFunctionDefinedOnAllServers(
        'world'
      );
    assert.deepEqual(invoke_result, {
      server_1: {
        state: 'ok',
        result: 'hello: world'
      },
      server_2: {
        state: 'ok',
        result: 'hello: world'
      }
    });
  } finally {
    await fixture.cleanup();
  }
});

test('all_servers returns mixed per-server results when one server auth fails.', async () => {
  const fixture = await BuildMtlsDualServerFixture({
    tls_material,
    server_1_client_api_key: 'valid_api_key',
    server_2_client_api_key: 'invalid_api_key',
    server_1_auth_map: {
      valid_api_key: ['all_privileges']
    },
    server_2_auth_map: {
      valid_api_key: ['all_privileges']
    }
  });

  try {
    const invoke_result = await fixture.networkprocedurecallclient.all_servers.call.WPCFunction2();
    assert.equal(invoke_result.server_1.state, 'ok');
    assert.equal(invoke_result.server_2.state, 'error');

    if (invoke_result.server_1.state === 'ok') {
      assert.equal(invoke_result.server_1.result, 'wpc_function_2_result');
    }

    if (invoke_result.server_2.state === 'error') {
      assert.equal(invoke_result.server_2.error.code, 'authentication_failed');
    }
  } finally {
    await fixture.cleanup();
  }
});

test('all_servers constant/dependency/function lifecycle succeeds across two servers.', async () => {
  const fixture = await BuildMtlsDualServerFixture({
    tls_material,
    server_1_client_api_key: 'valid_api_key',
    server_2_client_api_key: 'valid_api_key',
    server_1_auth_map: {
      valid_api_key: ['all_privileges']
    },
    server_2_auth_map: {
      valid_api_key: ['all_privileges']
    }
  });

  try {
    const define_dependency_result =
      await fixture.networkprocedurecallclient.all_servers.defineDependency({
        alias: 'path_dep',
        module_specifier: 'node:path'
      });
    assert.equal(define_dependency_result.server_1.state, 'ok');
    assert.equal(define_dependency_result.server_2.state, 'ok');

    const define_constant_result =
      await fixture.networkprocedurecallclient.all_servers.defineConstant({
        name: 'SERVICE_PREFIX',
        value: 'api-v1'
      });
    assert.equal(define_constant_result.server_1.state, 'ok');
    assert.equal(define_constant_result.server_2.state, 'ok');

    const define_function_result =
      await fixture.networkprocedurecallclient.all_servers.defineFunction({
        name: 'RemotePathBasenameAllServers',
        worker_func: async function (file_path: unknown): Promise<string> {
          const path_module = (await wpc_import('path_dep')) as {
            basename: (value: string) => string;
          };
          const prefix = wpc_constant('SERVICE_PREFIX') as string;
          return `${prefix}:${path_module.basename(String(file_path))}`;
        }
      });
    assert.equal(define_function_result.server_1.state, 'ok');
    assert.equal(define_function_result.server_2.state, 'ok');

    const lifecycle_result =
      await fixture.networkprocedurecallclient.all_servers.call.RemotePathBasenameAllServers(
        '/tmp/test_dir/example.txt'
      );
    assert.deepEqual(lifecycle_result, {
      server_1: {
        state: 'ok',
        result: 'api-v1:example.txt'
      },
      server_2: {
        state: 'ok',
        result: 'api-v1:example.txt'
      }
    });

    const undefine_function_result =
      await fixture.networkprocedurecallclient.all_servers.undefineFunction({
        name: 'RemotePathBasenameAllServers'
      });
    assert.equal(undefine_function_result.server_1.state, 'ok');
    assert.equal(undefine_function_result.server_2.state, 'ok');

    const undefine_constant_result =
      await fixture.networkprocedurecallclient.all_servers.undefineConstant({
        name: 'SERVICE_PREFIX'
      });
    assert.equal(undefine_constant_result.server_1.state, 'ok');
    assert.equal(undefine_constant_result.server_2.state, 'ok');

    const undefine_dependency_result =
      await fixture.networkprocedurecallclient.all_servers.undefineDependency({
        alias: 'path_dep'
      });
    assert.equal(undefine_dependency_result.server_1.state, 'ok');
    assert.equal(undefine_dependency_result.server_2.state, 'ok');
  } finally {
    await fixture.cleanup();
  }
});

test('all_servers ping and disconnect return per-server status.', async () => {
  const fixture = await BuildMtlsDualServerFixture({
    tls_material,
    server_1_client_api_key: 'valid_api_key',
    server_2_client_api_key: 'valid_api_key',
    server_1_auth_map: {
      valid_api_key: ['all_privileges']
    },
    server_2_auth_map: {
      valid_api_key: ['all_privileges']
    }
  });

  try {
    const ping_result = await fixture.networkprocedurecallclient.all_servers.ping();
    assert.equal(ping_result.server_1.state, 'ok');
    assert.equal(ping_result.server_2.state, 'ok');

    const disconnect_result = await fixture.networkprocedurecallclient.all_servers.disconnect();
    assert.equal(disconnect_result.server_1.state, 'ok');
    assert.equal(disconnect_result.server_2.state, 'ok');
  } finally {
    await fixture.cleanup();
  }
});

test('client constructor rejects reserved server key name all_servers.', async () => {
  const tcp_remote_port = await GetFreeTcpPort();

  assert.throws(() => {
    new NetworkProcedureCallClient({
      servers: {
        all_servers: {
          network: {
            host: '127.0.0.1',
            tcp_remote_port
          },
          tls_mtls: {
            key_pem: tls_material.client_key_pem,
            cert_pem: tls_material.client_cert_pem,
            ca_pem: tls_material.ca_cert_pem,
            servername: 'localhost',
            min_version: 'TLSv1.3'
          },
          authentication: {
            api_key: 'valid_api_key'
          }
        }
      }
    });
  }, /reserved server_name "all_servers"/);
});
