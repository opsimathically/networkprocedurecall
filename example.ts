/**
 * Example overview:
 *
 * 1. TLS material bootstrap:
 *    - The example uses `/tmp/networkprocedurecallexample/` for local cert/key files.
 *    - If CA/server/client cert material already exists, it is reused.
 *    - Otherwise it generates a self-signed CA, then signs both server and client certs with it.
 *
 * 2. Worker runtime:
 *    - Two `WorkerProcedureCall` instances are created (one per server).
 *    - Each server has a sample worker function (`WPCFunction2`) and active workers.
 *
 * 3. Network server (mTLS):
 *    - Two `NetworkProcedureCall` servers are started on localhost:6767 and localhost:6768.
 *    - The auth callback validates API key and confirms TLS peer identity metadata exists.
 *    - On success, privileges are returned (`all_privileges` in this example).
 *
 * 4. Network client (mTLS):
 *    - `NetworkProcedureCallClient` connects to both servers with client cert/key and trusted CA.
 *    - Hostname validation is enforced with `servername: 'localhost'`.
 *    - The client authenticates via API key inside the encrypted mTLS channel.
 *
 * 5. RPC invocation + cleanup using `all_servers`:
 *    - Uses `networkprocedurecallclient.all_servers` to define dependency/constant/function on both servers.
 *    - Invokes the remote function on all servers and prints per-server result maps.
 *    - Undefines dependency/constant/function on all servers and shows post-undefine error results.
 *    - Disconnects all client sessions and stops both servers and both worker runtimes.
 */
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

import { WorkerProcedureCall } from '@opsimathically/workerprocedurecall';

import {
  NetworkProcedureCall,
  NetworkProcedureCallClient
} from './src/classes/networkprocedurecall/NetworkProcedureCall.class';

type tls_material_paths_t = {
  base_dir_path: string;
  ca_key_path: string;
  ca_cert_path: string;
  ca_serial_path: string;
  server_key_path: string;
  server_csr_path: string;
  server_cert_path: string;
  server_ext_path: string;
  client_key_path: string;
  client_csr_path: string;
  client_cert_path: string;
  client_ext_path: string;
};

type tls_material_contents_t = {
  ca_cert_pem: string;
  server_key_pem: string;
  server_cert_pem: string;
  client_key_pem: string;
  client_cert_pem: string;
};

function GetTlsMaterialPaths(): tls_material_paths_t {
  const base_dir_path = '/tmp/networkprocedurecallexample';

  return {
    base_dir_path,
    ca_key_path: path.join(base_dir_path, 'ca.key.pem'),
    ca_cert_path: path.join(base_dir_path, 'ca.cert.pem'),
    ca_serial_path: path.join(base_dir_path, 'ca.cert.srl'),
    server_key_path: path.join(base_dir_path, 'server.key.pem'),
    server_csr_path: path.join(base_dir_path, 'server.csr.pem'),
    server_cert_path: path.join(base_dir_path, 'server.cert.pem'),
    server_ext_path: path.join(base_dir_path, 'server.ext'),
    client_key_path: path.join(base_dir_path, 'client.key.pem'),
    client_csr_path: path.join(base_dir_path, 'client.csr.pem'),
    client_cert_path: path.join(base_dir_path, 'client.cert.pem'),
    client_ext_path: path.join(base_dir_path, 'client.ext')
  };
}

function RunOpenSsl(params: { args: string[]; cwd: string }): void {
  try {
    execFileSync('openssl', params.args, {
      cwd: params.cwd,
      stdio: 'pipe'
    });
  } catch (error) {
    throw new Error(
      `OpenSSL command failed. Ensure openssl is installed and available on PATH. Command: openssl ${params.args.join(' ')}`
    );
  }
}

function TlsMaterialExists(params: {
  tls_material_paths: tls_material_paths_t;
}): boolean {
  const { tls_material_paths } = params;

  return (
    fs.existsSync(tls_material_paths.ca_key_path) &&
    fs.existsSync(tls_material_paths.ca_cert_path) &&
    fs.existsSync(tls_material_paths.server_key_path) &&
    fs.existsSync(tls_material_paths.server_cert_path) &&
    fs.existsSync(tls_material_paths.client_key_path) &&
    fs.existsSync(tls_material_paths.client_cert_path)
  );
}

function GenerateTlsMaterial(params: {
  tls_material_paths: tls_material_paths_t;
}): void {
  const { tls_material_paths } = params;

  fs.rmSync(tls_material_paths.base_dir_path, { recursive: true, force: true });
  fs.mkdirSync(tls_material_paths.base_dir_path, { recursive: true });

  fs.writeFileSync(
    tls_material_paths.server_ext_path,
    [
      'subjectAltName=DNS:localhost,IP:127.0.0.1',
      'extendedKeyUsage=serverAuth',
      'keyUsage=digitalSignature,keyEncipherment'
    ].join('\n'),
    'utf8'
  );

  fs.writeFileSync(
    tls_material_paths.client_ext_path,
    [
      'extendedKeyUsage=clientAuth',
      'keyUsage=digitalSignature,keyEncipherment',
      'subjectAltName=URI:spiffe://networkprocedurecall/example-client'
    ].join('\n'),
    'utf8'
  );

  RunOpenSsl({
    cwd: tls_material_paths.base_dir_path,
    args: [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-sha256',
      '-nodes',
      '-keyout',
      tls_material_paths.ca_key_path,
      '-out',
      tls_material_paths.ca_cert_path,
      '-days',
      '365',
      '-subj',
      '/CN=NetworkProcedureCall Example CA'
    ]
  });

  RunOpenSsl({
    cwd: tls_material_paths.base_dir_path,
    args: [
      'req',
      '-new',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      tls_material_paths.server_key_path,
      '-out',
      tls_material_paths.server_csr_path,
      '-subj',
      '/CN=localhost'
    ]
  });

  RunOpenSsl({
    cwd: tls_material_paths.base_dir_path,
    args: [
      'x509',
      '-req',
      '-in',
      tls_material_paths.server_csr_path,
      '-CA',
      tls_material_paths.ca_cert_path,
      '-CAkey',
      tls_material_paths.ca_key_path,
      '-CAcreateserial',
      '-CAserial',
      tls_material_paths.ca_serial_path,
      '-out',
      tls_material_paths.server_cert_path,
      '-days',
      '365',
      '-sha256',
      '-extfile',
      tls_material_paths.server_ext_path
    ]
  });

  RunOpenSsl({
    cwd: tls_material_paths.base_dir_path,
    args: [
      'req',
      '-new',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      tls_material_paths.client_key_path,
      '-out',
      tls_material_paths.client_csr_path,
      '-subj',
      '/CN=networkprocedurecall-example-client'
    ]
  });

  RunOpenSsl({
    cwd: tls_material_paths.base_dir_path,
    args: [
      'x509',
      '-req',
      '-in',
      tls_material_paths.client_csr_path,
      '-CA',
      tls_material_paths.ca_cert_path,
      '-CAkey',
      tls_material_paths.ca_key_path,
      '-CAserial',
      tls_material_paths.ca_serial_path,
      '-out',
      tls_material_paths.client_cert_path,
      '-days',
      '365',
      '-sha256',
      '-extfile',
      tls_material_paths.client_ext_path
    ]
  });
}

function EnsureTlsMaterialExists(params: {
  tls_material_paths: tls_material_paths_t;
}): 'reused' | 'generated' {
  const { tls_material_paths } = params;

  if (TlsMaterialExists({ tls_material_paths })) {
    return 'reused';
  }

  GenerateTlsMaterial({ tls_material_paths });
  return 'generated';
}

function ReadTlsMaterial(params: {
  tls_material_paths: tls_material_paths_t;
}): tls_material_contents_t {
  const { tls_material_paths } = params;

  return {
    ca_cert_pem: fs.readFileSync(tls_material_paths.ca_cert_path, 'utf8'),
    server_key_pem: fs.readFileSync(tls_material_paths.server_key_path, 'utf8'),
    server_cert_pem: fs.readFileSync(
      tls_material_paths.server_cert_path,
      'utf8'
    ),
    client_key_pem: fs.readFileSync(tls_material_paths.client_key_path, 'utf8'),
    client_cert_pem: fs.readFileSync(
      tls_material_paths.client_cert_path,
      'utf8'
    )
  };
}

(async function () {
  const tls_material_paths = GetTlsMaterialPaths();
  const tls_material_state = EnsureTlsMaterialExists({ tls_material_paths });
  if (tls_material_state === 'generated') {
    console.log(
      `Generated self-signed example TLS materials in ${tls_material_paths.base_dir_path}.`
    );
  } else {
    console.log(
      `Reusing existing example TLS materials from ${tls_material_paths.base_dir_path}.`
    );
  }
  const tls_material = ReadTlsMaterial({ tls_material_paths });

  const workerprocedurecall_server_1 = new WorkerProcedureCall({
    call_timeout_ms: 30_000,
    control_timeout_ms: 10_000,
    restart_on_failure: true,
    max_restarts_per_worker: 3,
    max_pending_calls_per_worker: 1_000,
    restart_base_delay_ms: 100,
    restart_max_delay_ms: 5_000,
    restart_jitter_ms: 100
  });

  const workerprocedurecall_server_2 = new WorkerProcedureCall({
    call_timeout_ms: 30_000,
    control_timeout_ms: 10_000,
    restart_on_failure: true,
    max_restarts_per_worker: 3,
    max_pending_calls_per_worker: 1_000,
    restart_base_delay_ms: 100,
    restart_max_delay_ms: 5_000,
    restart_jitter_ms: 100
  });

  await workerprocedurecall_server_1.defineWorkerFunction({
    name: 'WPCFunction2',
    worker_func: async function (): Promise<string> {
      return 'networkprocedurecall_example_ok_server_1';
    }
  });

  await workerprocedurecall_server_2.defineWorkerFunction({
    name: 'WPCFunction2',
    worker_func: async function (): Promise<string> {
      return 'networkprocedurecall_example_ok_server_2';
    }
  });

  await workerprocedurecall_server_1.startWorkers({ count: 2 });
  await workerprocedurecall_server_2.startWorkers({ count: 2 });

  const networkprocedurecall_server_1 = new NetworkProcedureCall({
    workerprocedurecall: workerprocedurecall_server_1
  });

  const networkprocedurecall_server_2 = new NetworkProcedureCall({
    workerprocedurecall: workerprocedurecall_server_2
  });

  const auth_callback = async function (params: {
    api_key: string;
    remote_address: string;
    tls_peer_fingerprint256?: string;
  }) {
    if (
      params.api_key === 'test_api_key_1' &&
      params.tls_peer_fingerprint256
    ) {
      return {
        state: 'authenticated' as const,
        privileges: ['all_privileges' as const]
      };
    }

    return 'failed' as const;
  };

  await networkprocedurecall_server_1.start({
    information: {
      server_name: 'server_1'
    },
    network: {
      tcp_listen_port: 6767,
      bind_addr: '127.0.0.1'
    },
    tls_mtls: {
      key_pem: tls_material.server_key_pem,
      cert_pem: tls_material.server_cert_pem,
      ca_pem: tls_material.ca_cert_pem,
      min_version: 'TLSv1.3'
    },
    auth_callback
  });

  await networkprocedurecall_server_2.start({
    information: {
      server_name: 'server_2'
    },
    network: {
      tcp_listen_port: 6768,
      bind_addr: '127.0.0.1'
    },
    tls_mtls: {
      key_pem: tls_material.server_key_pem,
      cert_pem: tls_material.server_cert_pem,
      ca_pem: tls_material.ca_cert_pem,
      min_version: 'TLSv1.3'
    },
    auth_callback
  });

  const networkprocedurecallclient = new NetworkProcedureCallClient({
    servers: {
      server_1: {
        network: {
          host: '127.0.0.1',
          tcp_remote_port: 6767
        },
        tls_mtls: {
          key_pem: tls_material.client_key_pem,
          cert_pem: tls_material.client_cert_pem,
          ca_pem: tls_material.ca_cert_pem,
          servername: 'localhost',
          min_version: 'TLSv1.3'
        },
        authentication: {
          api_key: 'test_api_key_1'
        }
      },
      server_2: {
        network: {
          host: '127.0.0.1',
          tcp_remote_port: 6768
        },
        tls_mtls: {
          key_pem: tls_material.client_key_pem,
          cert_pem: tls_material.client_cert_pem,
          ca_pem: tls_material.ca_cert_pem,
          servername: 'localhost',
          min_version: 'TLSv1.3'
        },
        authentication: {
          api_key: 'test_api_key_1'
        }
      }
    }
  });

  const define_dependency_results = await networkprocedurecallclient.all_servers.defineDependency({
    alias: 'path_dep',
    module_specifier: 'node:path'
  });
  console.log('all_servers.defineDependency results:', define_dependency_results);

  const define_constant_results = await networkprocedurecallclient.all_servers.defineConstant({
    name: 'SERVICE_PREFIX',
    value: 'api-v1'
  });
  console.log('all_servers.defineConstant results:', define_constant_results);

  const define_function_results = await networkprocedurecallclient.all_servers.defineFunction({
    name: 'SomeFunctionDefinedOnAllServers',
    worker_func: async function (file_path: unknown): Promise<string> {
      const path_module = (await wpc_import('path_dep')) as {
        basename: (value: string) => string;
      };

      const prefix = wpc_constant('SERVICE_PREFIX') as string;
      return `${prefix}:${path_module.basename(String(file_path))}`;
    }
  });
  console.log('all_servers.defineFunction results:', define_function_results);

  const single_server_result = await networkprocedurecallclient.server_1.call.WPCFunction2();
  console.log('single server call result (server_1):', single_server_result);

  const all_servers_call_results =
    await networkprocedurecallclient.all_servers.call.SomeFunctionDefinedOnAllServers(
      '/tmp/some_nested_dir/example_file.txt'
    );
  console.log('all_servers.call.SomeFunctionDefinedOnAllServers results:', all_servers_call_results);

  const undefine_function_results = await networkprocedurecallclient.all_servers.undefineFunction({
    name: 'SomeFunctionDefinedOnAllServers'
  });
  console.log('all_servers.undefineFunction results:', undefine_function_results);

  const undefine_constant_results = await networkprocedurecallclient.all_servers.undefineConstant({
    name: 'SERVICE_PREFIX'
  });
  console.log('all_servers.undefineConstant results:', undefine_constant_results);

  const undefine_dependency_results = await networkprocedurecallclient.all_servers.undefineDependency({
    alias: 'path_dep'
  });
  console.log('all_servers.undefineDependency results:', undefine_dependency_results);

  const post_undefine_call_results =
    await networkprocedurecallclient.all_servers.call.SomeFunctionDefinedOnAllServers(
      '/tmp/will_fail.txt'
    );
  console.log('post-undefine all_servers call results:', post_undefine_call_results);

  const disconnect_results = await networkprocedurecallclient.all_servers.disconnect();
  console.log('all_servers.disconnect results:', disconnect_results);

  await networkprocedurecall_server_1.stop();
  await networkprocedurecall_server_2.stop();
  await workerprocedurecall_server_1.stopWorkers();
  await workerprocedurecall_server_2.stopWorkers();
})();
