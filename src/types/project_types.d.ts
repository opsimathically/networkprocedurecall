import type {
  WorkerProcedureCall,
  define_worker_constant_params_t,
  define_worker_dependency_params_t,
  define_worker_function_params_t,
  undefine_worker_constant_params_t,
  undefine_worker_dependency_params_t,
  undefine_worker_function_params_t
} from '@opsimathically/workerprocedurecall';

export type privilege_name_t =
  | 'invoke_functions'
  | 'define_functions'
  | 'undefine_functions'
  | 'define_constants'
  | 'undefine_constants'
  | 'define_dependencies'
  | 'undefine_dependencies'
  | 'admin_privileges'
  | 'all_privileges';

export type networkprocedurecall_auth_success_t = {
  state: 'authenticated';
  privileges: privilege_name_t[];
};

export type tls_min_version_t = 'TLSv1.2' | 'TLSv1.3';

export type networkprocedurecall_auth_callback_t = (params: {
  api_key: string;
  remote_address: string;
  tls_peer_subject?: string;
  tls_peer_san?: string;
  tls_peer_fingerprint256?: string;
  tls_peer_serial_number?: string;
}) => Promise<'failed' | networkprocedurecall_auth_success_t>;

export type networkprocedurecall_server_tls_mtls_params_t = {
  key_pem: string;
  cert_pem: string;
  ca_pem: string;
  crl_pem?: string;
  min_version?: tls_min_version_t;
  cipher_suites?: string;
  handshake_timeout_ms?: number;
  request_timeout_ms?: number;
  max_frame_bytes?: number;
};

export type networkprocedurecall_rate_limiter_params_t = {
  enabled?: boolean;
  tokens_per_interval?: number;
  interval_ms?: number;
  burst_tokens?: number;
  disconnect_on_limit?: boolean;
};

export type networkprocedurecall_abuse_connection_controls_t = {
  max_concurrent_sockets?: number;
  max_concurrent_handshakes?: number;
  max_unauthenticated_sessions?: number;
  global_connection_window_ms?: number;
  global_max_new_connections_per_window?: number;
  per_ip_max_new_connections_per_window?: number;
  tls_handshake_timeout_ms?: number;
  auth_message_timeout_ms?: number;
  max_pre_auth_frame_bytes?: number;
  max_post_auth_frame_bytes?: number;
};

export type networkprocedurecall_abuse_auth_controls_t = {
  pending_auth_window_ms?: number;
  max_pending_auth_attempts_per_ip_per_window?: number;
  failed_auth_window_ms?: number;
  max_failed_auth_per_ip_per_window?: number;
  max_failed_auth_per_api_key_per_window?: number;
  block_duration_ms?: number;
  enable_blocklist?: boolean;
};

export type networkprocedurecall_abuse_request_controls_t = {
  max_in_flight_requests_per_connection?: number;
  per_connection?: networkprocedurecall_rate_limiter_params_t;
  per_api_key?: networkprocedurecall_rate_limiter_params_t;
  per_ip?: networkprocedurecall_rate_limiter_params_t;
};

export type networkprocedurecall_abuse_observability_controls_t = {
  enable_console_log?: boolean;
};

export type networkprocedurecall_abuse_controls_t = {
  connection_controls?: networkprocedurecall_abuse_connection_controls_t;
  auth_controls?: networkprocedurecall_abuse_auth_controls_t;
  request_controls?: networkprocedurecall_abuse_request_controls_t;
  observability?: networkprocedurecall_abuse_observability_controls_t;
};

export type networkprocedurecall_abuse_metrics_t = {
  connection_accepted_count: number;
  connection_rejected_count: number;
  handshake_limited_count: number;
  handshake_timeout_count: number;
  handshake_failure_count: number;
  auth_failure_count: number;
  auth_throttled_count: number;
  rate_limited_per_connection_count: number;
  rate_limited_per_api_key_count: number;
  rate_limited_per_ip_count: number;
  rate_limited_in_flight_count: number;
  active_socket_count: number;
  active_handshake_count: number;
  active_unauthenticated_session_count: number;
};

export type networkprocedurecall_server_start_params_t = {
  information: {
    server_name: string;
  };
  network: {
    bind_addr: string;
    tcp_listen_port: number;
  };
  tls_mtls: networkprocedurecall_server_tls_mtls_params_t;
  abuse_controls?: networkprocedurecall_abuse_controls_t;
  auth_callback: networkprocedurecall_auth_callback_t;
};

export type networkprocedurecall_constructor_params_t = {
  workerprocedurecall: WorkerProcedureCall;
};

export type networkprocedurecall_client_server_tls_mtls_params_t = {
  key_pem: string;
  cert_pem: string;
  ca_pem: string;
  servername: string;
  crl_pem?: string;
  min_version?: tls_min_version_t;
  cipher_suites?: string;
  handshake_timeout_ms?: number;
  request_timeout_ms?: number;
  max_frame_bytes?: number;
};

export type networkprocedurecall_client_server_definition_t = {
  network: {
    host: string;
    tcp_remote_port: number;
  };
  tls_mtls: networkprocedurecall_client_server_tls_mtls_params_t;
  authentication: {
    api_key: string;
  };
};

export type networkprocedurecall_client_constructor_params_t = {
  servers: Record<string, networkprocedurecall_client_server_definition_t>;
};

export type networkprocedurecall_remote_error_t = {
  code: string;
  message: string;
  details?: unknown;
};

export type networkprocedurecall_response_t = {
  request_id: string;
  state: 'ok' | 'error';
  result?: unknown;
  error?: networkprocedurecall_remote_error_t;
};

export type networkprocedurecall_operation_name_t =
  | 'invoke_function'
  | 'define_function'
  | 'undefine_function'
  | 'define_constant'
  | 'undefine_constant'
  | 'define_dependency'
  | 'undefine_dependency';

export type remote_define_function_payload_t = {
  name: string;
  function_source: string;
  source_hash_sha256: string;
};

export type remote_define_function_input_t =
  | remote_define_function_payload_t
  | define_worker_function_remote_adapter_params_t;

export type remote_undefine_function_payload_t = undefine_worker_function_params_t;
export type remote_define_constant_payload_t = define_worker_constant_params_t;
export type remote_undefine_constant_payload_t = undefine_worker_constant_params_t;
export type remote_define_dependency_payload_t = define_worker_dependency_params_t;
export type remote_undefine_dependency_payload_t = undefine_worker_dependency_params_t;
export type remote_invoke_function_payload_t = {
  function_name: string;
  call_args: unknown[];
};

export type networkprocedurecall_request_payload_t =
  | remote_invoke_function_payload_t
  | remote_define_function_payload_t
  | remote_undefine_function_payload_t
  | remote_define_constant_payload_t
  | remote_undefine_constant_payload_t
  | remote_define_dependency_payload_t
  | remote_undefine_dependency_payload_t;

export type networkprocedurecall_request_t = {
  request_id: string;
  operation: networkprocedurecall_operation_name_t;
  payload: networkprocedurecall_request_payload_t;
};

export type networkprocedurecall_client_server_call_proxy_t = {
  [function_name: string]: (...call_args: unknown[]) => Promise<unknown>;
};

export type all_servers_operation_result_t<result_t> =
  | {
      state: 'ok';
      result: result_t;
    }
  | {
      state: 'error';
      error: networkprocedurecall_remote_error_t;
    };

export type all_servers_operation_result_map_t<result_t> = Record<
  string,
  all_servers_operation_result_t<result_t>
>;

export type networkprocedurecall_client_all_servers_call_proxy_t = {
  [function_name: string]: (
    ...call_args: unknown[]
  ) => Promise<all_servers_operation_result_map_t<unknown>>;
};

export type networkprocedurecall_client_server_methods_t = {
  call: networkprocedurecall_client_server_call_proxy_t;
  ping(): Promise<void>;
  defineFunction(params: remote_define_function_input_t): Promise<void>;
  undefineFunction(params: remote_undefine_function_payload_t): Promise<void>;
  defineConstant(params: remote_define_constant_payload_t): Promise<void>;
  undefineConstant(params: remote_undefine_constant_payload_t): Promise<void>;
  defineDependency(params: remote_define_dependency_payload_t): Promise<void>;
  undefineDependency(params: remote_undefine_dependency_payload_t): Promise<void>;
  disconnect(): Promise<void>;
};

export type networkprocedurecall_client_all_servers_methods_t = {
  call: networkprocedurecall_client_all_servers_call_proxy_t;
  ping(): Promise<all_servers_operation_result_map_t<null>>;
  defineFunction(
    params: remote_define_function_input_t
  ): Promise<all_servers_operation_result_map_t<null>>;
  undefineFunction(
    params: remote_undefine_function_payload_t
  ): Promise<all_servers_operation_result_map_t<null>>;
  defineConstant(
    params: remote_define_constant_payload_t
  ): Promise<all_servers_operation_result_map_t<null>>;
  undefineConstant(
    params: remote_undefine_constant_payload_t
  ): Promise<all_servers_operation_result_map_t<null>>;
  defineDependency(
    params: remote_define_dependency_payload_t
  ): Promise<all_servers_operation_result_map_t<null>>;
  undefineDependency(
    params: remote_undefine_dependency_payload_t
  ): Promise<all_servers_operation_result_map_t<null>>;
  disconnect(): Promise<all_servers_operation_result_map_t<null>>;
};

export type networkprocedurecall_client_server_map_t = Record<
  string,
  networkprocedurecall_client_server_methods_t
>;

export type networkprocedurecall_runtime_auth_state_t = {
  is_authenticated: boolean;
  privileges: Set<privilege_name_t>;
};

export type define_worker_function_remote_adapter_params_t = Omit<
  define_worker_function_params_t,
  'worker_func'
> & {
  worker_func: (...call_args: unknown[]) => Promise<unknown> | unknown;
};
