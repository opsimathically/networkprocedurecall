import crypto from 'node:crypto';
import net from 'node:net';
import tls from 'node:tls';

import type {
  WorkerProcedureCall,
  define_worker_dependency_params_t,
  define_worker_function_params_t
} from '@opsimathically/workerprocedurecall';

import type {
  all_servers_operation_result_map_t,
  networkprocedurecall_abuse_controls_t,
  networkprocedurecall_abuse_metrics_t,
  networkprocedurecall_abuse_request_controls_t,
  networkprocedurecall_auth_callback_t,
  networkprocedurecall_client_all_servers_call_proxy_t,
  networkprocedurecall_client_all_servers_methods_t,
  networkprocedurecall_client_constructor_params_t,
  networkprocedurecall_client_server_call_proxy_t,
  networkprocedurecall_client_server_definition_t,
  networkprocedurecall_client_server_methods_t,
  networkprocedurecall_constructor_params_t,
  networkprocedurecall_operation_name_t,
  networkprocedurecall_remote_error_t,
  networkprocedurecall_request_t,
  networkprocedurecall_request_payload_t,
  networkprocedurecall_response_t,
  networkprocedurecall_runtime_auth_state_t,
  networkprocedurecall_server_start_params_t,
  networkprocedurecall_server_tls_mtls_params_t,
  privilege_name_t,
  remote_define_dependency_payload_t,
  remote_define_function_input_t,
  remote_define_constant_payload_t,
  remote_define_function_payload_t,
  remote_invoke_function_payload_t,
  remote_undefine_constant_payload_t,
  remote_undefine_dependency_payload_t,
  remote_undefine_function_payload_t,
  tls_min_version_t
} from '../../types/project_types';

const DEFAULT_HANDSHAKE_TIMEOUT_MS = 10_000;
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_FRAME_BYTES = 1_048_576;

const ADMIN_MANAGED_PRIVILEGES = new Set<privilege_name_t>([
  'define_functions',
  'undefine_functions',
  'define_constants',
  'undefine_constants',
  'define_dependencies',
  'undefine_dependencies'
]);

type normalized_rate_limiter_params_t = {
  enabled: boolean;
  tokens_per_interval: number;
  interval_ms: number;
  burst_tokens: number;
  disconnect_on_limit: boolean;
};

type normalized_abuse_controls_t = {
  connection_controls: {
    max_concurrent_sockets: number;
    max_concurrent_handshakes: number;
    max_unauthenticated_sessions: number;
    global_connection_window_ms: number;
    global_max_new_connections_per_window: number;
    per_ip_max_new_connections_per_window: number;
    tls_handshake_timeout_ms: number;
    auth_message_timeout_ms: number;
    max_pre_auth_frame_bytes: number;
    max_post_auth_frame_bytes: number;
  };
  auth_controls: {
    pending_auth_window_ms: number;
    max_pending_auth_attempts_per_ip_per_window: number;
    failed_auth_window_ms: number;
    max_failed_auth_per_ip_per_window: number;
    max_failed_auth_per_api_key_per_window: number;
    block_duration_ms: number;
    enable_blocklist: boolean;
  };
  request_controls: {
    max_in_flight_requests_per_connection: number;
    per_connection: normalized_rate_limiter_params_t;
    per_api_key: normalized_rate_limiter_params_t;
    per_ip: normalized_rate_limiter_params_t;
  };
  observability: {
    enable_console_log: boolean;
  };
};

type keyed_rate_limiter_entry_t = {
  rate_limiter: TokenBucketRateLimiter;
  last_seen_ms: number;
};

type rate_limit_decision_t = {
  allowed: true;
} | {
  allowed: false;
  code: 'rate_limited' | 'auth_throttled' | 'connection_limited' | 'handshake_limited';
  retry_after_ms: number;
  message: string;
  disconnect_on_limit: boolean;
  details?: Record<string, unknown>;
};

const DEFAULT_ABUSE_CONTROLS: normalized_abuse_controls_t = {
  connection_controls: {
    max_concurrent_sockets: 1024,
    max_concurrent_handshakes: 256,
    max_unauthenticated_sessions: 256,
    global_connection_window_ms: 1_000,
    global_max_new_connections_per_window: 512,
    per_ip_max_new_connections_per_window: 64,
    tls_handshake_timeout_ms: 5_000,
    auth_message_timeout_ms: 5_000,
    max_pre_auth_frame_bytes: 64 * 1024,
    max_post_auth_frame_bytes: DEFAULT_MAX_FRAME_BYTES
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
      interval_ms: 1_000,
      burst_tokens: 400,
      disconnect_on_limit: false
    },
    per_api_key: {
      enabled: true,
      tokens_per_interval: 1_000,
      interval_ms: 1_000,
      burst_tokens: 2_000,
      disconnect_on_limit: false
    },
    per_ip: {
      enabled: true,
      tokens_per_interval: 500,
      interval_ms: 1_000,
      burst_tokens: 1_000,
      disconnect_on_limit: false
    }
  },
  observability: {
    enable_console_log: false
  }
};

const DEFAULT_ABUSE_METRICS: networkprocedurecall_abuse_metrics_t = {
  connection_accepted_count: 0,
  connection_rejected_count: 0,
  handshake_limited_count: 0,
  handshake_timeout_count: 0,
  handshake_failure_count: 0,
  auth_failure_count: 0,
  auth_throttled_count: 0,
  rate_limited_per_connection_count: 0,
  rate_limited_per_api_key_count: 0,
  rate_limited_per_ip_count: 0,
  rate_limited_in_flight_count: 0,
  active_socket_count: 0,
  active_handshake_count: 0,
  active_unauthenticated_session_count: 0
};

type normalized_tls_mtls_params_t = {
  key_pem: string;
  cert_pem: string;
  ca_pem: string;
  crl_pem: string | null;
  min_version: tls_min_version_t;
  cipher_suites: string | null;
  handshake_timeout_ms: number;
  request_timeout_ms: number;
  max_frame_bytes: number;
};

type normalized_client_server_definition_t = {
  network: {
    host: string;
    tcp_remote_port: number;
  };
  tls_mtls: normalized_tls_mtls_params_t & {
    servername: string;
  };
  authentication: {
    api_key: string;
  };
};

type transport_message_t =
  | transport_auth_message_t
  | transport_auth_result_message_t
  | transport_request_message_t
  | transport_response_message_t
  | transport_ping_message_t
  | transport_pong_message_t
  | transport_error_message_t;

type transport_auth_message_t = {
  message_type: 'auth';
  api_key: string;
};

type transport_auth_result_message_t = {
  message_type: 'auth_result';
  state: 'authenticated' | 'failed';
  privileges?: privilege_name_t[];
};

type transport_request_message_t = {
  message_type: 'request';
  request: networkprocedurecall_request_t;
};

type transport_response_message_t = {
  message_type: 'response';
  response: networkprocedurecall_response_t;
};

type transport_ping_message_t = {
  message_type: 'ping';
  ping_id: string;
};

type transport_pong_message_t = {
  message_type: 'pong';
  ping_id: string;
};

type transport_error_message_t = {
  message_type: 'error';
  error: networkprocedurecall_remote_error_t;
};

type pending_request_t = {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timeout_handle: NodeJS.Timeout;
};

type pending_waiter_t = {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timeout_handle: NodeJS.Timeout;
};

type raw_socket_state_t = {
  is_tracked_connection: boolean;
  is_handshake_in_progress: boolean;
  close_reason?: string;
};

interface networkprocedurecall_server_session_i {
  close(): Promise<void>;
}

interface networkprocedurecall_client_session_i {
  invokeFunction(params: { function_name: string; call_args: unknown[] }): Promise<unknown>;
  defineFunction(params: remote_define_function_input_t): Promise<void>;
  undefineFunction(params: remote_undefine_function_payload_t): Promise<void>;
  defineConstant(params: remote_define_constant_payload_t): Promise<void>;
  undefineConstant(params: remote_undefine_constant_payload_t): Promise<void>;
  defineDependency(params: remote_define_dependency_payload_t): Promise<void>;
  undefineDependency(params: remote_undefine_dependency_payload_t): Promise<void>;
  ping(): Promise<void>;
  disconnect(): Promise<void>;
}

class RemoteRequestError extends Error {
  public readonly code: string;
  public readonly details?: unknown;

  constructor(params: { code: string; message: string; details?: unknown }) {
    super(params.message);
    this.code = params.code;
    this.details = params.details;
  }
}

function AssertPositiveInteger(params: { value: number; label: string }): void {
  const { value, label } = params;
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer.`);
  }
}

function CloneAbuseMetrics(params: {
  abuse_metrics: networkprocedurecall_abuse_metrics_t;
}): networkprocedurecall_abuse_metrics_t {
  return {
    connection_accepted_count: params.abuse_metrics.connection_accepted_count,
    connection_rejected_count: params.abuse_metrics.connection_rejected_count,
    handshake_limited_count: params.abuse_metrics.handshake_limited_count,
    handshake_timeout_count: params.abuse_metrics.handshake_timeout_count,
    handshake_failure_count: params.abuse_metrics.handshake_failure_count,
    auth_failure_count: params.abuse_metrics.auth_failure_count,
    auth_throttled_count: params.abuse_metrics.auth_throttled_count,
    rate_limited_per_connection_count: params.abuse_metrics.rate_limited_per_connection_count,
    rate_limited_per_api_key_count: params.abuse_metrics.rate_limited_per_api_key_count,
    rate_limited_per_ip_count: params.abuse_metrics.rate_limited_per_ip_count,
    rate_limited_in_flight_count: params.abuse_metrics.rate_limited_in_flight_count,
    active_socket_count: params.abuse_metrics.active_socket_count,
    active_handshake_count: params.abuse_metrics.active_handshake_count,
    active_unauthenticated_session_count: params.abuse_metrics.active_unauthenticated_session_count
  };
}

function NormalizeRateLimiterParams(params: {
  input: networkprocedurecall_abuse_request_controls_t['per_connection'] | undefined;
  defaults: normalized_rate_limiter_params_t;
  label_prefix: string;
}): normalized_rate_limiter_params_t {
  const input = params.input ?? {};

  const normalized_rate_limiter: normalized_rate_limiter_params_t = {
    enabled: input.enabled ?? params.defaults.enabled,
    tokens_per_interval: input.tokens_per_interval ?? params.defaults.tokens_per_interval,
    interval_ms: input.interval_ms ?? params.defaults.interval_ms,
    burst_tokens: input.burst_tokens ?? params.defaults.burst_tokens,
    disconnect_on_limit: input.disconnect_on_limit ?? params.defaults.disconnect_on_limit
  };

  AssertPositiveInteger({
    value: normalized_rate_limiter.tokens_per_interval,
    label: `${params.label_prefix}.tokens_per_interval`
  });
  AssertPositiveInteger({
    value: normalized_rate_limiter.interval_ms,
    label: `${params.label_prefix}.interval_ms`
  });
  AssertPositiveInteger({
    value: normalized_rate_limiter.burst_tokens,
    label: `${params.label_prefix}.burst_tokens`
  });

  return normalized_rate_limiter;
}

function NormalizeAbuseControls(params: {
  abuse_controls: networkprocedurecall_abuse_controls_t | undefined;
  max_frame_bytes: number;
}): normalized_abuse_controls_t {
  const abuse_controls = params.abuse_controls ?? {};

  const connection_controls = abuse_controls.connection_controls ?? {};
  const auth_controls = abuse_controls.auth_controls ?? {};
  const request_controls = abuse_controls.request_controls ?? {};
  const observability_controls = abuse_controls.observability ?? {};

  const normalized_abuse_controls: normalized_abuse_controls_t = {
    connection_controls: {
      max_concurrent_sockets:
        connection_controls.max_concurrent_sockets ??
        DEFAULT_ABUSE_CONTROLS.connection_controls.max_concurrent_sockets,
      max_concurrent_handshakes:
        connection_controls.max_concurrent_handshakes ??
        DEFAULT_ABUSE_CONTROLS.connection_controls.max_concurrent_handshakes,
      max_unauthenticated_sessions:
        connection_controls.max_unauthenticated_sessions ??
        DEFAULT_ABUSE_CONTROLS.connection_controls.max_unauthenticated_sessions,
      global_connection_window_ms:
        connection_controls.global_connection_window_ms ??
        DEFAULT_ABUSE_CONTROLS.connection_controls.global_connection_window_ms,
      global_max_new_connections_per_window:
        connection_controls.global_max_new_connections_per_window ??
        DEFAULT_ABUSE_CONTROLS.connection_controls.global_max_new_connections_per_window,
      per_ip_max_new_connections_per_window:
        connection_controls.per_ip_max_new_connections_per_window ??
        DEFAULT_ABUSE_CONTROLS.connection_controls.per_ip_max_new_connections_per_window,
      tls_handshake_timeout_ms:
        connection_controls.tls_handshake_timeout_ms ??
        DEFAULT_ABUSE_CONTROLS.connection_controls.tls_handshake_timeout_ms,
      auth_message_timeout_ms:
        connection_controls.auth_message_timeout_ms ??
        DEFAULT_ABUSE_CONTROLS.connection_controls.auth_message_timeout_ms,
      max_pre_auth_frame_bytes:
        connection_controls.max_pre_auth_frame_bytes ??
        Math.min(
          params.max_frame_bytes,
          DEFAULT_ABUSE_CONTROLS.connection_controls.max_pre_auth_frame_bytes
        ),
      max_post_auth_frame_bytes:
        connection_controls.max_post_auth_frame_bytes ?? params.max_frame_bytes
    },
    auth_controls: {
      pending_auth_window_ms:
        auth_controls.pending_auth_window_ms ??
        DEFAULT_ABUSE_CONTROLS.auth_controls.pending_auth_window_ms,
      max_pending_auth_attempts_per_ip_per_window:
        auth_controls.max_pending_auth_attempts_per_ip_per_window ??
        DEFAULT_ABUSE_CONTROLS.auth_controls.max_pending_auth_attempts_per_ip_per_window,
      failed_auth_window_ms:
        auth_controls.failed_auth_window_ms ??
        DEFAULT_ABUSE_CONTROLS.auth_controls.failed_auth_window_ms,
      max_failed_auth_per_ip_per_window:
        auth_controls.max_failed_auth_per_ip_per_window ??
        DEFAULT_ABUSE_CONTROLS.auth_controls.max_failed_auth_per_ip_per_window,
      max_failed_auth_per_api_key_per_window:
        auth_controls.max_failed_auth_per_api_key_per_window ??
        DEFAULT_ABUSE_CONTROLS.auth_controls.max_failed_auth_per_api_key_per_window,
      block_duration_ms:
        auth_controls.block_duration_ms ?? DEFAULT_ABUSE_CONTROLS.auth_controls.block_duration_ms,
      enable_blocklist:
        auth_controls.enable_blocklist ?? DEFAULT_ABUSE_CONTROLS.auth_controls.enable_blocklist
    },
    request_controls: {
      max_in_flight_requests_per_connection:
        request_controls.max_in_flight_requests_per_connection ??
        DEFAULT_ABUSE_CONTROLS.request_controls.max_in_flight_requests_per_connection,
      per_connection: NormalizeRateLimiterParams({
        input: request_controls.per_connection,
        defaults: DEFAULT_ABUSE_CONTROLS.request_controls.per_connection,
        label_prefix: 'abuse_controls.request_controls.per_connection'
      }),
      per_api_key: NormalizeRateLimiterParams({
        input: request_controls.per_api_key,
        defaults: DEFAULT_ABUSE_CONTROLS.request_controls.per_api_key,
        label_prefix: 'abuse_controls.request_controls.per_api_key'
      }),
      per_ip: NormalizeRateLimiterParams({
        input: request_controls.per_ip,
        defaults: DEFAULT_ABUSE_CONTROLS.request_controls.per_ip,
        label_prefix: 'abuse_controls.request_controls.per_ip'
      })
    },
    observability: {
      enable_console_log:
        observability_controls.enable_console_log ??
        DEFAULT_ABUSE_CONTROLS.observability.enable_console_log
    }
  };

  AssertPositiveInteger({
    value: normalized_abuse_controls.connection_controls.max_concurrent_sockets,
    label: 'abuse_controls.connection_controls.max_concurrent_sockets'
  });
  AssertPositiveInteger({
    value: normalized_abuse_controls.connection_controls.max_concurrent_handshakes,
    label: 'abuse_controls.connection_controls.max_concurrent_handshakes'
  });
  AssertPositiveInteger({
    value: normalized_abuse_controls.connection_controls.max_unauthenticated_sessions,
    label: 'abuse_controls.connection_controls.max_unauthenticated_sessions'
  });
  AssertPositiveInteger({
    value: normalized_abuse_controls.connection_controls.global_connection_window_ms,
    label: 'abuse_controls.connection_controls.global_connection_window_ms'
  });
  AssertPositiveInteger({
    value: normalized_abuse_controls.connection_controls.global_max_new_connections_per_window,
    label: 'abuse_controls.connection_controls.global_max_new_connections_per_window'
  });
  AssertPositiveInteger({
    value: normalized_abuse_controls.connection_controls.per_ip_max_new_connections_per_window,
    label: 'abuse_controls.connection_controls.per_ip_max_new_connections_per_window'
  });
  AssertPositiveInteger({
    value: normalized_abuse_controls.connection_controls.tls_handshake_timeout_ms,
    label: 'abuse_controls.connection_controls.tls_handshake_timeout_ms'
  });
  AssertPositiveInteger({
    value: normalized_abuse_controls.connection_controls.auth_message_timeout_ms,
    label: 'abuse_controls.connection_controls.auth_message_timeout_ms'
  });
  AssertPositiveInteger({
    value: normalized_abuse_controls.connection_controls.max_pre_auth_frame_bytes,
    label: 'abuse_controls.connection_controls.max_pre_auth_frame_bytes'
  });
  AssertPositiveInteger({
    value: normalized_abuse_controls.connection_controls.max_post_auth_frame_bytes,
    label: 'abuse_controls.connection_controls.max_post_auth_frame_bytes'
  });

  if (
    normalized_abuse_controls.connection_controls.max_pre_auth_frame_bytes >
    normalized_abuse_controls.connection_controls.max_post_auth_frame_bytes
  ) {
    throw new Error(
      'abuse_controls.connection_controls.max_pre_auth_frame_bytes must be <= max_post_auth_frame_bytes.'
    );
  }

  if (normalized_abuse_controls.connection_controls.max_post_auth_frame_bytes > params.max_frame_bytes) {
    throw new Error(
      'abuse_controls.connection_controls.max_post_auth_frame_bytes cannot exceed tls_mtls.max_frame_bytes.'
    );
  }

  AssertPositiveInteger({
    value: normalized_abuse_controls.auth_controls.pending_auth_window_ms,
    label: 'abuse_controls.auth_controls.pending_auth_window_ms'
  });
  AssertPositiveInteger({
    value: normalized_abuse_controls.auth_controls.max_pending_auth_attempts_per_ip_per_window,
    label: 'abuse_controls.auth_controls.max_pending_auth_attempts_per_ip_per_window'
  });
  AssertPositiveInteger({
    value: normalized_abuse_controls.auth_controls.failed_auth_window_ms,
    label: 'abuse_controls.auth_controls.failed_auth_window_ms'
  });
  AssertPositiveInteger({
    value: normalized_abuse_controls.auth_controls.max_failed_auth_per_ip_per_window,
    label: 'abuse_controls.auth_controls.max_failed_auth_per_ip_per_window'
  });
  AssertPositiveInteger({
    value: normalized_abuse_controls.auth_controls.max_failed_auth_per_api_key_per_window,
    label: 'abuse_controls.auth_controls.max_failed_auth_per_api_key_per_window'
  });
  AssertPositiveInteger({
    value: normalized_abuse_controls.auth_controls.block_duration_ms,
    label: 'abuse_controls.auth_controls.block_duration_ms'
  });

  AssertPositiveInteger({
    value: normalized_abuse_controls.request_controls.max_in_flight_requests_per_connection,
    label: 'abuse_controls.request_controls.max_in_flight_requests_per_connection'
  });

  return normalized_abuse_controls;
}

function PruneWindowTimestamps(params: {
  timestamps: number[];
  now_ms: number;
  window_ms: number;
}): void {
  const minimum_time = params.now_ms - params.window_ms;
  while (params.timestamps.length > 0 && params.timestamps[0] <= minimum_time) {
    params.timestamps.shift();
  }
}

function AllowSlidingWindowEvent(params: {
  timestamps: number[];
  now_ms: number;
  window_ms: number;
  max_events: number;
}): {
  allowed: boolean;
  retry_after_ms: number;
} {
  PruneWindowTimestamps({
    timestamps: params.timestamps,
    now_ms: params.now_ms,
    window_ms: params.window_ms
  });

  if (params.timestamps.length >= params.max_events) {
    const oldest_event_time = params.timestamps[0];
    const retry_after_ms =
      oldest_event_time !== undefined
        ? Math.max(1, params.window_ms - (params.now_ms - oldest_event_time))
        : params.window_ms;
    return {
      allowed: false,
      retry_after_ms
    };
  }

  params.timestamps.push(params.now_ms);
  return {
    allowed: true,
    retry_after_ms: 0
  };
}

function BuildSocketKey(params: { socket: net.Socket | tls.TLSSocket }): string {
  const remote_address = params.socket.remoteAddress ?? 'unknown';
  const remote_port = params.socket.remotePort ?? -1;
  const local_port = params.socket.localPort ?? -1;
  return `${remote_address}:${remote_port}->${local_port}`;
}

class TokenBucketRateLimiter {
  private available_tokens: number;
  private last_refill_time_ms: number;

  constructor(private readonly params: normalized_rate_limiter_params_t) {
    this.available_tokens = params.burst_tokens;
    this.last_refill_time_ms = Date.now();
  }

  consume(params: { token_cost?: number; now_ms?: number }): {
    allowed: boolean;
    retry_after_ms: number;
  } {
    const token_cost = params.token_cost ?? 1;
    const now_ms = params.now_ms ?? Date.now();

    if (!this.params.enabled) {
      return {
        allowed: true,
        retry_after_ms: 0
      };
    }

    this.refill({
      now_ms
    });

    if (this.available_tokens >= token_cost) {
      this.available_tokens -= token_cost;
      return {
        allowed: true,
        retry_after_ms: 0
      };
    }

    const missing_tokens = token_cost - this.available_tokens;
    const tokens_per_ms = this.params.tokens_per_interval / this.params.interval_ms;
    const retry_after_ms = Math.max(1, Math.ceil(missing_tokens / tokens_per_ms));
    return {
      allowed: false,
      retry_after_ms
    };
  }

  private refill(params: { now_ms: number }): void {
    if (params.now_ms <= this.last_refill_time_ms) {
      return;
    }

    const elapsed_ms = params.now_ms - this.last_refill_time_ms;
    const refill_amount =
      (elapsed_ms / this.params.interval_ms) * this.params.tokens_per_interval;

    this.available_tokens = Math.min(
      this.params.burst_tokens,
      this.available_tokens + refill_amount
    );
    this.last_refill_time_ms = params.now_ms;
  }
}

class NetworkProcedureCallAbuseController {
  private readonly metrics: networkprocedurecall_abuse_metrics_t = CloneAbuseMetrics({
    abuse_metrics: DEFAULT_ABUSE_METRICS
  });

  private global_connection_timestamps: number[] = [];
  private connection_timestamps_by_ip = new Map<string, number[]>();
  private pending_auth_attempt_timestamps_by_ip = new Map<string, number[]>();
  private failed_auth_timestamps_by_ip = new Map<string, number[]>();
  private failed_auth_timestamps_by_api_key = new Map<string, number[]>();
  private blocked_ip_until_by_ip = new Map<string, number>();
  private blocked_api_key_until_by_api_key = new Map<string, number>();
  private api_key_rate_limiter_by_api_key = new Map<string, keyed_rate_limiter_entry_t>();
  private ip_rate_limiter_by_ip = new Map<string, keyed_rate_limiter_entry_t>();

  constructor(private readonly controls: normalized_abuse_controls_t) {}

  getControls(): normalized_abuse_controls_t {
    return this.controls;
  }

  getMetrics(): networkprocedurecall_abuse_metrics_t {
    return CloneAbuseMetrics({
      abuse_metrics: this.metrics
    });
  }

  onRawConnectionOpenAttempt(params: { remote_address: string }): rate_limit_decision_t {
    const now_ms = Date.now();
    this.pruneAllExpiringState({
      now_ms
    });

    const ip_blocked_until = this.blocked_ip_until_by_ip.get(params.remote_address);
    if (ip_blocked_until && ip_blocked_until > now_ms) {
      this.metrics.connection_rejected_count += 1;
      this.metrics.auth_throttled_count += 1;
      return {
        allowed: false,
        code: 'auth_throttled',
        retry_after_ms: Math.max(1, ip_blocked_until - now_ms),
        message: 'Connection blocked due to excessive authentication failures.',
        disconnect_on_limit: true
      };
    }

    if (
      this.metrics.active_socket_count + 1 >
      this.controls.connection_controls.max_concurrent_sockets
    ) {
      this.metrics.connection_rejected_count += 1;
      return {
        allowed: false,
        code: 'connection_limited',
        retry_after_ms: 200,
        message: 'max_concurrent_sockets limit reached.',
        disconnect_on_limit: true
      };
    }

    if (
      this.metrics.active_handshake_count + 1 >
      this.controls.connection_controls.max_concurrent_handshakes
    ) {
      this.metrics.connection_rejected_count += 1;
      this.metrics.handshake_limited_count += 1;
      return {
        allowed: false,
        code: 'handshake_limited',
        retry_after_ms: 200,
        message: 'max_concurrent_handshakes limit reached.',
        disconnect_on_limit: true
      };
    }

    const global_window = AllowSlidingWindowEvent({
      timestamps: this.global_connection_timestamps,
      now_ms,
      window_ms: this.controls.connection_controls.global_connection_window_ms,
      max_events: this.controls.connection_controls.global_max_new_connections_per_window
    });
    if (!global_window.allowed) {
      this.metrics.connection_rejected_count += 1;
      return {
        allowed: false,
        code: 'connection_limited',
        retry_after_ms: global_window.retry_after_ms,
        message: 'Global new connection rate limit exceeded.',
        disconnect_on_limit: true,
        details: {
          scope: 'global_connection_window'
        }
      };
    }

    const ip_connection_timestamps = this.getOrCreateTimestampsByKey({
      map: this.connection_timestamps_by_ip,
      key: params.remote_address
    });
    const ip_window = AllowSlidingWindowEvent({
      timestamps: ip_connection_timestamps,
      now_ms,
      window_ms: this.controls.connection_controls.global_connection_window_ms,
      max_events: this.controls.connection_controls.per_ip_max_new_connections_per_window
    });
    if (!ip_window.allowed) {
      this.metrics.connection_rejected_count += 1;
      return {
        allowed: false,
        code: 'connection_limited',
        retry_after_ms: ip_window.retry_after_ms,
        message: 'Per-IP new connection rate limit exceeded.',
        disconnect_on_limit: true,
        details: {
          scope: 'ip_connection_window'
        }
      };
    }

    this.metrics.active_socket_count += 1;
    this.metrics.active_handshake_count += 1;
    this.metrics.connection_accepted_count += 1;
    return {
      allowed: true
    };
  }

  onRawConnectionClosed(params: {
    was_tracked_connection: boolean;
    was_handshake_in_progress: boolean;
    close_reason?: string;
  }): void {
    if (!params.was_tracked_connection) {
      return;
    }

    this.metrics.active_socket_count = Math.max(0, this.metrics.active_socket_count - 1);

    if (params.was_handshake_in_progress) {
      this.metrics.active_handshake_count = Math.max(0, this.metrics.active_handshake_count - 1);
      if (params.close_reason === 'tls_handshake_timeout') {
        this.metrics.handshake_timeout_count += 1;
      } else {
        this.metrics.handshake_failure_count += 1;
      }
    }
  }

  onTlsHandshakeFinished(): rate_limit_decision_t {
    this.metrics.active_handshake_count = Math.max(0, this.metrics.active_handshake_count - 1);

    if (
      this.metrics.active_unauthenticated_session_count + 1 >
      this.controls.connection_controls.max_unauthenticated_sessions
    ) {
      this.metrics.handshake_limited_count += 1;
      return {
        allowed: false,
        code: 'handshake_limited',
        retry_after_ms: 200,
        message: 'max_unauthenticated_sessions limit reached.',
        disconnect_on_limit: true
      };
    }

    this.metrics.active_unauthenticated_session_count += 1;
    return {
      allowed: true
    };
  }

  releaseUnauthenticatedSession(): void {
    this.metrics.active_unauthenticated_session_count = Math.max(
      0,
      this.metrics.active_unauthenticated_session_count - 1
    );
  }

  onAuthAttempt(params: {
    remote_address: string;
    api_key: string;
  }): rate_limit_decision_t {
    const now_ms = Date.now();
    this.pruneAllExpiringState({
      now_ms
    });

    const ip_blocked_until = this.blocked_ip_until_by_ip.get(params.remote_address);
    if (ip_blocked_until && ip_blocked_until > now_ms) {
      this.metrics.auth_throttled_count += 1;
      return {
        allowed: false,
        code: 'auth_throttled',
        retry_after_ms: Math.max(1, ip_blocked_until - now_ms),
        message: 'IP is temporarily blocked due to failed authentication attempts.',
        disconnect_on_limit: true
      };
    }

    const api_key_blocked_until = this.blocked_api_key_until_by_api_key.get(params.api_key);
    if (api_key_blocked_until && api_key_blocked_until > now_ms) {
      this.metrics.auth_throttled_count += 1;
      return {
        allowed: false,
        code: 'auth_throttled',
        retry_after_ms: Math.max(1, api_key_blocked_until - now_ms),
        message: 'API key is temporarily blocked due to failed authentication attempts.',
        disconnect_on_limit: true
      };
    }

    const pending_auth_timestamps = this.getOrCreateTimestampsByKey({
      map: this.pending_auth_attempt_timestamps_by_ip,
      key: params.remote_address
    });
    const pending_auth_window = AllowSlidingWindowEvent({
      timestamps: pending_auth_timestamps,
      now_ms,
      window_ms: this.controls.auth_controls.pending_auth_window_ms,
      max_events: this.controls.auth_controls.max_pending_auth_attempts_per_ip_per_window
    });
    if (!pending_auth_window.allowed) {
      this.metrics.auth_throttled_count += 1;
      return {
        allowed: false,
        code: 'auth_throttled',
        retry_after_ms: pending_auth_window.retry_after_ms,
        message: 'Too many authentication attempts from this IP.',
        disconnect_on_limit: true,
        details: {
          scope: 'pending_auth_attempts_per_ip'
        }
      };
    }

    return {
      allowed: true
    };
  }

  onAuthFailure(params: { remote_address: string; api_key: string }): void {
    const now_ms = Date.now();
    this.metrics.auth_failure_count += 1;

    const ip_failures = this.getOrCreateTimestampsByKey({
      map: this.failed_auth_timestamps_by_ip,
      key: params.remote_address
    });
    ip_failures.push(now_ms);
    PruneWindowTimestamps({
      timestamps: ip_failures,
      now_ms,
      window_ms: this.controls.auth_controls.failed_auth_window_ms
    });

    const api_key_failures = this.getOrCreateTimestampsByKey({
      map: this.failed_auth_timestamps_by_api_key,
      key: params.api_key
    });
    api_key_failures.push(now_ms);
    PruneWindowTimestamps({
      timestamps: api_key_failures,
      now_ms,
      window_ms: this.controls.auth_controls.failed_auth_window_ms
    });

    if (!this.controls.auth_controls.enable_blocklist) {
      return;
    }

    if (ip_failures.length >= this.controls.auth_controls.max_failed_auth_per_ip_per_window) {
      this.blocked_ip_until_by_ip.set(
        params.remote_address,
        now_ms + this.controls.auth_controls.block_duration_ms
      );
    }

    if (
      api_key_failures.length >=
      this.controls.auth_controls.max_failed_auth_per_api_key_per_window
    ) {
      this.blocked_api_key_until_by_api_key.set(
        params.api_key,
        now_ms + this.controls.auth_controls.block_duration_ms
      );
    }
  }

  evaluateSharedRequestRateLimit(params: {
    remote_address: string;
    api_key: string;
  }): rate_limit_decision_t {
    const now_ms = Date.now();
    this.pruneAllExpiringState({
      now_ms
    });

    if (this.controls.request_controls.per_api_key.enabled) {
      const api_key_limiter = this.getOrCreateKeyedRateLimiter({
        map: this.api_key_rate_limiter_by_api_key,
        key: params.api_key,
        limiter_params: this.controls.request_controls.per_api_key,
        now_ms
      });
      const api_key_result = api_key_limiter.rate_limiter.consume({
        now_ms
      });
      if (!api_key_result.allowed) {
        this.metrics.rate_limited_per_api_key_count += 1;
        return {
          allowed: false,
          code: 'rate_limited',
          retry_after_ms: api_key_result.retry_after_ms,
          message: 'Per-API-key request rate limit exceeded.',
          disconnect_on_limit: this.controls.request_controls.per_api_key.disconnect_on_limit,
          details: {
            scope: 'per_api_key'
          }
        };
      }
      api_key_limiter.last_seen_ms = now_ms;
    }

    if (this.controls.request_controls.per_ip.enabled) {
      const ip_limiter = this.getOrCreateKeyedRateLimiter({
        map: this.ip_rate_limiter_by_ip,
        key: params.remote_address,
        limiter_params: this.controls.request_controls.per_ip,
        now_ms
      });
      const ip_result = ip_limiter.rate_limiter.consume({
        now_ms
      });
      if (!ip_result.allowed) {
        this.metrics.rate_limited_per_ip_count += 1;
        return {
          allowed: false,
          code: 'rate_limited',
          retry_after_ms: ip_result.retry_after_ms,
          message: 'Per-IP request rate limit exceeded.',
          disconnect_on_limit: this.controls.request_controls.per_ip.disconnect_on_limit,
          details: {
            scope: 'per_ip'
          }
        };
      }
      ip_limiter.last_seen_ms = now_ms;
    }

    return {
      allowed: true
    };
  }

  onPerConnectionRateLimited(): void {
    this.metrics.rate_limited_per_connection_count += 1;
  }

  onInFlightRateLimited(): void {
    this.metrics.rate_limited_in_flight_count += 1;
  }

  onHandshakeAuthorizationFailure(): void {
    this.metrics.handshake_failure_count += 1;
  }

  log(params: { message: string }): void {
    if (!this.controls.observability.enable_console_log) {
      return;
    }
    console.warn(`[networkprocedurecall][abuse] ${params.message}`);
  }

  private pruneAllExpiringState(params: { now_ms: number }): void {
    this.pruneTimestampMap({
      map: this.connection_timestamps_by_ip,
      window_ms: this.controls.connection_controls.global_connection_window_ms,
      now_ms: params.now_ms
    });
    PruneWindowTimestamps({
      timestamps: this.global_connection_timestamps,
      now_ms: params.now_ms,
      window_ms: this.controls.connection_controls.global_connection_window_ms
    });
    this.pruneTimestampMap({
      map: this.pending_auth_attempt_timestamps_by_ip,
      window_ms: this.controls.auth_controls.pending_auth_window_ms,
      now_ms: params.now_ms
    });
    this.pruneTimestampMap({
      map: this.failed_auth_timestamps_by_ip,
      window_ms: this.controls.auth_controls.failed_auth_window_ms,
      now_ms: params.now_ms
    });
    this.pruneTimestampMap({
      map: this.failed_auth_timestamps_by_api_key,
      window_ms: this.controls.auth_controls.failed_auth_window_ms,
      now_ms: params.now_ms
    });

    for (const [ip_key, blocked_until] of this.blocked_ip_until_by_ip.entries()) {
      if (blocked_until <= params.now_ms) {
        this.blocked_ip_until_by_ip.delete(ip_key);
      }
    }
    for (const [api_key, blocked_until] of this.blocked_api_key_until_by_api_key.entries()) {
      if (blocked_until <= params.now_ms) {
        this.blocked_api_key_until_by_api_key.delete(api_key);
      }
    }

    this.pruneRateLimiterMap({
      map: this.api_key_rate_limiter_by_api_key,
      now_ms: params.now_ms,
      interval_ms: this.controls.request_controls.per_api_key.interval_ms
    });
    this.pruneRateLimiterMap({
      map: this.ip_rate_limiter_by_ip,
      now_ms: params.now_ms,
      interval_ms: this.controls.request_controls.per_ip.interval_ms
    });
  }

  private pruneTimestampMap(params: {
    map: Map<string, number[]>;
    window_ms: number;
    now_ms: number;
  }): void {
    for (const [map_key, timestamps] of params.map.entries()) {
      PruneWindowTimestamps({
        timestamps,
        now_ms: params.now_ms,
        window_ms: params.window_ms
      });
      if (timestamps.length === 0) {
        params.map.delete(map_key);
      }
    }
  }

  private pruneRateLimiterMap(params: {
    map: Map<string, keyed_rate_limiter_entry_t>;
    now_ms: number;
    interval_ms: number;
  }): void {
    const max_idle_ms = Math.max(params.interval_ms * 10, 60_000);
    for (const [limiter_key, limiter_entry] of params.map.entries()) {
      if (params.now_ms - limiter_entry.last_seen_ms > max_idle_ms) {
        params.map.delete(limiter_key);
      }
    }
  }

  private getOrCreateTimestampsByKey(params: {
    map: Map<string, number[]>;
    key: string;
  }): number[] {
    const existing_timestamps = params.map.get(params.key);
    if (existing_timestamps) {
      return existing_timestamps;
    }

    const new_timestamps: number[] = [];
    params.map.set(params.key, new_timestamps);
    return new_timestamps;
  }

  private getOrCreateKeyedRateLimiter(params: {
    map: Map<string, keyed_rate_limiter_entry_t>;
    key: string;
    limiter_params: normalized_rate_limiter_params_t;
    now_ms: number;
  }): keyed_rate_limiter_entry_t {
    const existing_entry = params.map.get(params.key);
    if (existing_entry) {
      return existing_entry;
    }

    const new_entry: keyed_rate_limiter_entry_t = {
      rate_limiter: new TokenBucketRateLimiter(params.limiter_params),
      last_seen_ms: params.now_ms
    };
    params.map.set(params.key, new_entry);
    return new_entry;
  }
}

function GetErrorMessage(params: { error: unknown }): string {
  if (params.error instanceof Error) {
    return params.error.message;
  }
  if (typeof params.error === 'string') {
    return params.error;
  }
  return 'Unknown error.';
}

function CreateRemoteError(params: {
  code: string;
  message: string;
  details?: unknown;
}): networkprocedurecall_remote_error_t {
  return {
    code: params.code,
    message: params.message,
    details: params.details
  };
}

function NormalizeTlsMtlsParams(params: {
  tls_mtls: networkprocedurecall_server_tls_mtls_params_t;
  require_servername: boolean;
  servername?: string;
}): normalized_tls_mtls_params_t & { servername?: string } {
  const { tls_mtls } = params;

  const handshake_timeout_ms = tls_mtls.handshake_timeout_ms ?? DEFAULT_HANDSHAKE_TIMEOUT_MS;
  const request_timeout_ms = tls_mtls.request_timeout_ms ?? DEFAULT_REQUEST_TIMEOUT_MS;
  const max_frame_bytes = tls_mtls.max_frame_bytes ?? DEFAULT_MAX_FRAME_BYTES;
  const min_version = tls_mtls.min_version ?? 'TLSv1.3';

  AssertPositiveInteger({ value: handshake_timeout_ms, label: 'handshake_timeout_ms' });
  AssertPositiveInteger({ value: request_timeout_ms, label: 'request_timeout_ms' });
  AssertPositiveInteger({ value: max_frame_bytes, label: 'max_frame_bytes' });

  if (tls_mtls.key_pem.length === 0) {
    throw new Error('tls_mtls.key_pem must be a non-empty PEM string.');
  }
  if (tls_mtls.cert_pem.length === 0) {
    throw new Error('tls_mtls.cert_pem must be a non-empty PEM string.');
  }
  if (tls_mtls.ca_pem.length === 0) {
    throw new Error('tls_mtls.ca_pem must be a non-empty PEM string.');
  }

  const normalized_params: normalized_tls_mtls_params_t & { servername?: string } = {
    key_pem: tls_mtls.key_pem,
    cert_pem: tls_mtls.cert_pem,
    ca_pem: tls_mtls.ca_pem,
    crl_pem: typeof tls_mtls.crl_pem === 'string' && tls_mtls.crl_pem.length > 0
      ? tls_mtls.crl_pem
      : null,
    min_version,
    cipher_suites:
      typeof tls_mtls.cipher_suites === 'string' && tls_mtls.cipher_suites.length > 0
        ? tls_mtls.cipher_suites
        : null,
    handshake_timeout_ms,
    request_timeout_ms,
    max_frame_bytes
  };

  if (params.require_servername) {
    if (typeof params.servername !== 'string' || params.servername.length === 0) {
      throw new Error('tls_mtls.servername must be a non-empty string for client connections.');
    }

    normalized_params.servername = params.servername;
  }

  return normalized_params;
}

function NormalizeClientServerDefinition(params: {
  server_definition: networkprocedurecall_client_server_definition_t;
}): normalized_client_server_definition_t {
  const { server_definition } = params;

  if (server_definition.network.host.length === 0) {
    throw new Error('host must be a non-empty string.');
  }

  AssertPositiveInteger({ value: server_definition.network.tcp_remote_port, label: 'tcp_remote_port' });

  if (server_definition.authentication.api_key.length === 0) {
    throw new Error('api_key must be a non-empty string.');
  }

  const tls_mtls = NormalizeTlsMtlsParams({
    tls_mtls: server_definition.tls_mtls,
    require_servername: true,
    servername: server_definition.tls_mtls.servername
  });

  return {
    network: {
      host: server_definition.network.host,
      tcp_remote_port: server_definition.network.tcp_remote_port
    },
    tls_mtls: {
      ...tls_mtls,
      servername: tls_mtls.servername as string
    },
    authentication: {
      api_key: server_definition.authentication.api_key
    }
  };
}

function SerializeLengthPrefixedFrame(params: {
  payload: unknown;
  max_frame_bytes: number;
}): Buffer {
  const payload_json = JSON.stringify(params.payload);
  const payload_buffer = Buffer.from(payload_json, 'utf8');

  if (payload_buffer.length > params.max_frame_bytes) {
    throw new Error(
      `Outbound frame length ${payload_buffer.length} exceeds configured max_frame_bytes (${params.max_frame_bytes}).`
    );
  }

  const frame = Buffer.allocUnsafe(4 + payload_buffer.length);
  frame.writeUInt32BE(payload_buffer.length, 0);
  payload_buffer.copy(frame, 4);
  return frame;
}

function ParseJsonFrame(params: { frame: Buffer }): unknown {
  try {
    return JSON.parse(params.frame.toString('utf8'));
  } catch (error) {
    throw new Error(`Failed to parse frame JSON: ${GetErrorMessage({ error })}`);
  }
}

function ValidatePrivilegeList(params: { privileges: privilege_name_t[] }): void {
  for (const privilege_name of params.privileges) {
    if (
      privilege_name !== 'invoke_functions' &&
      privilege_name !== 'define_functions' &&
      privilege_name !== 'undefine_functions' &&
      privilege_name !== 'define_constants' &&
      privilege_name !== 'undefine_constants' &&
      privilege_name !== 'define_dependencies' &&
      privilege_name !== 'undefine_dependencies' &&
      privilege_name !== 'admin_privileges' &&
      privilege_name !== 'all_privileges'
    ) {
      throw new Error(`Unsupported privilege returned by auth_callback: ${privilege_name}`);
    }
  }
}

function HasPrivilege(params: {
  auth_state: networkprocedurecall_runtime_auth_state_t;
  required_privilege: privilege_name_t;
}): boolean {
  const { auth_state, required_privilege } = params;

  if (!auth_state.is_authenticated) {
    return false;
  }

  if (auth_state.privileges.has('all_privileges')) {
    return true;
  }

  if (required_privilege === 'invoke_functions') {
    return (
      auth_state.privileges.has('invoke_functions') ||
      auth_state.privileges.has('admin_privileges')
    );
  }

  if (ADMIN_MANAGED_PRIVILEGES.has(required_privilege)) {
    return (
      auth_state.privileges.has(required_privilege) ||
      auth_state.privileges.has('admin_privileges')
    );
  }

  return auth_state.privileges.has(required_privilege);
}

function RequiredPrivilegeForOperation(params: {
  operation: networkprocedurecall_operation_name_t;
}): privilege_name_t {
  if (params.operation === 'invoke_function') {
    return 'invoke_functions';
  }
  if (params.operation === 'define_function') {
    return 'define_functions';
  }
  if (params.operation === 'undefine_function') {
    return 'undefine_functions';
  }
  if (params.operation === 'define_constant') {
    return 'define_constants';
  }
  if (params.operation === 'define_dependency') {
    return 'define_dependencies';
  }
  if (params.operation === 'undefine_dependency') {
    return 'undefine_dependencies';
  }
  return 'undefine_constants';
}

function NormalizeRemoteInvokePayload(params: {
  payload: unknown;
}): remote_invoke_function_payload_t {
  const payload_value = params.payload as Record<string, unknown>;

  if (!payload_value || typeof payload_value !== 'object') {
    throw new Error('invoke_function payload must be an object.');
  }

  if (typeof payload_value.function_name !== 'string' || payload_value.function_name.length === 0) {
    throw new Error('invoke_function payload.function_name must be a non-empty string.');
  }

  if (!Array.isArray(payload_value.call_args)) {
    throw new Error('invoke_function payload.call_args must be an array.');
  }

  return {
    function_name: payload_value.function_name,
    call_args: payload_value.call_args
  };
}

function NormalizeRemoteDefineFunctionPayload(params: {
  payload: unknown;
}): remote_define_function_payload_t {
  const payload_value = params.payload as Record<string, unknown>;

  if (!payload_value || typeof payload_value !== 'object') {
    throw new Error('define_function payload must be an object.');
  }

  if (typeof payload_value.name !== 'string' || payload_value.name.length === 0) {
    throw new Error('define_function payload.name must be a non-empty string.');
  }

  if (
    typeof payload_value.function_source !== 'string' ||
    payload_value.function_source.length === 0
  ) {
    throw new Error('define_function payload.function_source must be a non-empty string.');
  }

  if (
    typeof payload_value.source_hash_sha256 !== 'string' ||
    payload_value.source_hash_sha256.length !== 64
  ) {
    throw new Error('define_function payload.source_hash_sha256 must be a sha256 hex string.');
  }

  return {
    name: payload_value.name,
    function_source: payload_value.function_source,
    source_hash_sha256: payload_value.source_hash_sha256
  };
}

function NormalizeRemoteDefineFunctionInput(params: {
  define_function_input: remote_define_function_input_t;
}): remote_define_function_payload_t {
  const { define_function_input } = params;

  const payload_value = define_function_input as Record<string, unknown>;
  if (typeof payload_value.worker_func === 'function') {
    if (typeof payload_value.name !== 'string' || payload_value.name.length === 0) {
      throw new Error('defineFunction name must be a non-empty string.');
    }

    const function_source = payload_value.worker_func.toString();
    if (function_source.length === 0) {
      throw new Error(`Function \"${payload_value.name}\" could not be serialized.`);
    }

    return CreateRemoteFunctionPayload({
      name: payload_value.name,
      function_source
    });
  }

  return NormalizeRemoteDefineFunctionPayload({
    payload: define_function_input
  });
}

function NormalizeRemoteDefineConstantPayload(params: {
  payload: unknown;
}): remote_define_constant_payload_t {
  const payload_value = params.payload as Record<string, unknown>;

  if (!payload_value || typeof payload_value !== 'object') {
    throw new Error('define_constant payload must be an object.');
  }

  if (typeof payload_value.name !== 'string' || payload_value.name.length === 0) {
    throw new Error('define_constant payload.name must be a non-empty string.');
  }

  return {
    name: payload_value.name,
    value: payload_value.value
  };
}

function NormalizeRemoteUndefineConstantPayload(params: {
  payload: unknown;
}): remote_undefine_constant_payload_t {
  const payload_value = params.payload as Record<string, unknown>;

  if (!payload_value || typeof payload_value !== 'object') {
    throw new Error('undefine_constant payload must be an object.');
  }

  if (typeof payload_value.name !== 'string' || payload_value.name.length === 0) {
    throw new Error('undefine_constant payload.name must be a non-empty string.');
  }

  return {
    name: payload_value.name
  };
}

function NormalizeRemoteUndefineFunctionPayload(params: {
  payload: unknown;
}): remote_undefine_function_payload_t {
  const payload_value = params.payload as Record<string, unknown>;

  if (!payload_value || typeof payload_value !== 'object') {
    throw new Error('undefine_function payload must be an object.');
  }

  if (typeof payload_value.name !== 'string' || payload_value.name.length === 0) {
    throw new Error('undefine_function payload.name must be a non-empty string.');
  }

  return {
    name: payload_value.name
  };
}

function NormalizeRemoteDefineDependencyPayload(params: {
  payload: unknown;
}): remote_define_dependency_payload_t {
  const payload_value = params.payload as Record<string, unknown>;

  if (!payload_value || typeof payload_value !== 'object') {
    throw new Error('define_dependency payload must be an object.');
  }

  if (typeof payload_value.alias !== 'string' || payload_value.alias.length === 0) {
    throw new Error('define_dependency payload.alias must be a non-empty string.');
  }

  if (
    typeof payload_value.module_specifier !== 'string' ||
    payload_value.module_specifier.length === 0
  ) {
    throw new Error('define_dependency payload.module_specifier must be a non-empty string.');
  }

  let export_name: string | undefined;
  if (typeof payload_value.export_name === 'string') {
    export_name = payload_value.export_name;
  }

  let is_default_export: boolean | undefined;
  if (typeof payload_value.is_default_export === 'boolean') {
    is_default_export = payload_value.is_default_export;
  }

  return {
    alias: payload_value.alias,
    module_specifier: payload_value.module_specifier,
    export_name,
    is_default_export
  };
}

function NormalizeRemoteUndefineDependencyPayload(params: {
  payload: unknown;
}): remote_undefine_dependency_payload_t {
  const payload_value = params.payload as Record<string, unknown>;

  if (!payload_value || typeof payload_value !== 'object') {
    throw new Error('undefine_dependency payload must be an object.');
  }

  if (typeof payload_value.alias !== 'string' || payload_value.alias.length === 0) {
    throw new Error('undefine_dependency payload.alias must be a non-empty string.');
  }

  return {
    alias: payload_value.alias
  };
}

function HashFunctionSourceSha256(params: { function_source: string }): string {
  return crypto
    .createHash('sha256')
    .update(params.function_source, 'utf8')
    .digest('hex');
}

function CompileRemoteFunction(params: {
  function_source: string;
}): (...call_args: unknown[]) => Promise<unknown> | unknown {
  let evaluated_function: unknown;

  try {
    evaluated_function = new Function(`"use strict"; return (${params.function_source});`)();
  } catch (error) {
    throw new Error(`Failed to parse remote function source: ${GetErrorMessage({ error })}`);
  }

  if (typeof evaluated_function !== 'function') {
    throw new Error('Remote function source must evaluate to a function.');
  }

  return evaluated_function as (...call_args: unknown[]) => Promise<unknown> | unknown;
}

async function RunWithTimeout<return_t>(params: {
  timeout_ms: number;
  callback: () => Promise<return_t>;
  timeout_message: string;
}): Promise<return_t> {
  return await new Promise<return_t>((resolve, reject) => {
    const timeout_handle = setTimeout(() => {
      reject(new Error(params.timeout_message));
    }, params.timeout_ms);

    params
      .callback()
      .then((return_value) => {
        clearTimeout(timeout_handle);
        resolve(return_value);
      })
      .catch((error) => {
        clearTimeout(timeout_handle);
        reject(error);
      });
  });
}

class LengthPrefixedFrameReader {
  private buffered_data = Buffer.alloc(0);

  constructor(
    private readonly max_frame_bytes: number,
    private readonly on_frame: (params: { frame: Buffer }) => void,
    private readonly on_error: (params: { error: Error }) => void
  ) {}

  pushData(params: { chunk: Buffer }): void {
    this.buffered_data = Buffer.concat([this.buffered_data, params.chunk]);

    while (this.buffered_data.length >= 4) {
      const frame_length = this.buffered_data.readUInt32BE(0);
      if (frame_length === 0) {
        this.on_error({ error: new Error('Received zero-length frame, which is invalid.') });
        return;
      }

      if (frame_length > this.max_frame_bytes) {
        this.on_error({
          error: new Error(
            `Received frame length ${frame_length} exceeding configured max_frame_bytes ${this.max_frame_bytes}.`
          )
        });
        return;
      }

      const required_length = 4 + frame_length;
      if (this.buffered_data.length < required_length) {
        return;
      }

      const frame = this.buffered_data.subarray(4, required_length);
      this.buffered_data = this.buffered_data.subarray(required_length);
      this.on_frame({ frame });
    }
  }
}

class NetworkProcedureCallServerSession implements networkprocedurecall_server_session_i {
  private readonly socket: tls.TLSSocket;
  private readonly workerprocedurecall: WorkerProcedureCall;
  private readonly auth_callback: networkprocedurecall_auth_callback_t;
  private readonly abuse_controller: NetworkProcedureCallAbuseController;
  private readonly request_timeout_ms: number;
  private readonly max_pre_auth_frame_bytes: number;
  private readonly max_post_auth_frame_bytes: number;
  private readonly max_in_flight_requests_per_connection: number;
  private readonly on_close: (params: { session: networkprocedurecall_server_session_i }) => void;
  private readonly remote_address: string;
  private readonly per_connection_request_rate_limiter: TokenBucketRateLimiter;

  private readonly auth_state: networkprocedurecall_runtime_auth_state_t = {
    is_authenticated: false,
    privileges: new Set<privilege_name_t>()
  };

  private readonly frame_reader: LengthPrefixedFrameReader;
  private lifecycle_state: 'handshaking' | 'ready' | 'closed' = 'handshaking';
  private authenticated_api_key: string | null = null;
  private in_flight_request_count = 0;
  private is_unauthenticated_session_tracked = true;
  private auth_message_timeout_handle: NodeJS.Timeout | null = null;

  constructor(params: {
    workerprocedurecall: WorkerProcedureCall;
    socket: tls.TLSSocket;
    auth_callback: networkprocedurecall_auth_callback_t;
    tls_mtls: normalized_tls_mtls_params_t;
    abuse_controller: NetworkProcedureCallAbuseController;
    on_close: (params: { session: networkprocedurecall_server_session_i }) => void;
  }) {
    this.socket = params.socket;
    this.workerprocedurecall = params.workerprocedurecall;
    this.auth_callback = params.auth_callback;
    this.abuse_controller = params.abuse_controller;
    this.request_timeout_ms = params.tls_mtls.request_timeout_ms;
    this.max_pre_auth_frame_bytes =
      params.abuse_controller.getControls().connection_controls.max_pre_auth_frame_bytes;
    this.max_post_auth_frame_bytes =
      params.abuse_controller.getControls().connection_controls.max_post_auth_frame_bytes;
    this.max_in_flight_requests_per_connection =
      params.abuse_controller.getControls().request_controls.max_in_flight_requests_per_connection;
    this.on_close = params.on_close;
    this.remote_address = this.socket.remoteAddress ?? 'unknown';
    this.per_connection_request_rate_limiter = new TokenBucketRateLimiter(
      params.abuse_controller.getControls().request_controls.per_connection
    );

    this.frame_reader = new LengthPrefixedFrameReader(
      Math.max(this.max_pre_auth_frame_bytes, this.max_post_auth_frame_bytes),
      ({ frame }) => {
        void this.handleFrame({ frame });
      },
      ({ error }) => {
        this.safeDestroy({ reason: `frame_error:${error.message}` });
      }
    );

    this.socket.setNoDelay(true);
    this.socket.setTimeout(params.abuse_controller.getControls().connection_controls.auth_message_timeout_ms);

    this.socket.on('timeout', () => {
      this.safeDestroy({ reason: 'socket_timeout' });
    });

    this.socket.on('data', (chunk: Buffer) => {
      this.frame_reader.pushData({ chunk });
    });

    this.socket.on('error', () => {
      this.safeDestroy({ reason: 'socket_error' });
    });

    this.socket.on('close', () => {
      if (this.lifecycle_state !== 'closed') {
        this.lifecycle_state = 'closed';
      }

      this.releaseUnauthenticatedSessionTracking();
      this.on_close({ session: this });
    });

    this.auth_message_timeout_handle = setTimeout(() => {
      this.safeDestroy({ reason: 'auth_message_timeout' });
    }, this.abuse_controller.getControls().connection_controls.auth_message_timeout_ms);
  }

  async close(): Promise<void> {
    if (this.lifecycle_state === 'closed') {
      return;
    }

    this.safeDestroy({ reason: 'session_close_requested' });
  }

  private async handleFrame(params: { frame: Buffer }): Promise<void> {
    if (this.lifecycle_state === 'closed') {
      return;
    }

    const frame_max_size =
      this.auth_state.is_authenticated ? this.max_post_auth_frame_bytes : this.max_pre_auth_frame_bytes;
    if (params.frame.length > frame_max_size) {
      this.safeDestroy({
        reason: `frame_exceeds_stage_limit:${params.frame.length}/${frame_max_size}`
      });
      return;
    }

    let message: transport_message_t;
    try {
      message = ParseJsonFrame({ frame: params.frame }) as transport_message_t;
    } catch (error) {
      this.safeDestroy({ reason: `invalid_frame:${GetErrorMessage({ error })}` });
      return;
    }

    if (message.message_type === 'auth') {
      await this.handleAuthMessage({ message });
      return;
    }

    if (!this.auth_state.is_authenticated) {
      await this.sendMessage({
        message: {
          message_type: 'error',
          error: CreateRemoteError({
            code: 'not_authenticated',
            message: 'Connection is not authenticated.'
          })
        }
      });
      this.safeDestroy({ reason: 'message_before_authentication' });
      return;
    }

    if (message.message_type === 'ping') {
      await this.sendMessage({
        message: {
          message_type: 'pong',
          ping_id: message.ping_id
        }
      });
      return;
    }

    if (message.message_type === 'request') {
      await this.handleRequest({ message });
      return;
    }

    await this.sendMessage({
      message: {
        message_type: 'error',
        error: CreateRemoteError({
          code: 'unsupported_message_type',
          message: `Unsupported message_type "${(message as { message_type: string }).message_type}".`
        })
      }
    });
  }

  private async handleAuthMessage(params: { message: transport_auth_message_t }): Promise<void> {
    if (this.auth_state.is_authenticated) {
      await this.sendMessage({
        message: {
          message_type: 'auth_result',
          state: 'failed'
        }
      });
      this.safeDestroy({ reason: 'duplicate_auth_attempt' });
      return;
    }

    if (typeof params.message.api_key !== 'string' || params.message.api_key.length === 0) {
      this.abuse_controller.onAuthFailure({
        remote_address: this.remote_address,
        api_key: ''
      });
      await this.sendMessage({
        message: {
          message_type: 'auth_result',
          state: 'failed'
        }
      });
      this.safeDestroy({ reason: 'invalid_api_key_shape' });
      return;
    }

    const auth_attempt_decision = this.abuse_controller.onAuthAttempt({
      remote_address: this.remote_address,
      api_key: params.message.api_key
    });
    if (!auth_attempt_decision.allowed) {
      await this.sendMessage({
        message: {
          message_type: 'error',
          error: CreateRemoteError({
            code: auth_attempt_decision.code,
            message: auth_attempt_decision.message,
            details: {
              retry_after_ms: auth_attempt_decision.retry_after_ms,
              ...(auth_attempt_decision.details ?? {})
            }
          })
        }
      });
      this.safeDestroy({ reason: 'auth_throttled' });
      return;
    }

    let auth_result: Awaited<ReturnType<networkprocedurecall_auth_callback_t>>;
    try {
      auth_result = await this.auth_callback(
        this.buildAuthCallbackParams({ api_key: params.message.api_key })
      );
    } catch (error) {
      await this.sendMessage({
        message: {
          message_type: 'auth_result',
          state: 'failed'
        }
      });
      this.abuse_controller.onAuthFailure({
        remote_address: this.remote_address,
        api_key: params.message.api_key
      });
      this.safeDestroy({ reason: `auth_callback_error:${GetErrorMessage({ error })}` });
      return;
    }

    if (auth_result === 'failed') {
      await this.sendMessage({
        message: {
          message_type: 'auth_result',
          state: 'failed'
        }
      });
      this.abuse_controller.onAuthFailure({
        remote_address: this.remote_address,
        api_key: params.message.api_key
      });
      this.safeDestroy({ reason: 'api_key_auth_failed' });
      return;
    }

    ValidatePrivilegeList({ privileges: auth_result.privileges });
    this.auth_state.is_authenticated = true;
    this.auth_state.privileges = new Set(auth_result.privileges);
    this.authenticated_api_key = params.message.api_key;
    this.lifecycle_state = 'ready';
    this.releaseUnauthenticatedSessionTracking();

    this.socket.setTimeout(0);
    if (this.auth_message_timeout_handle) {
      clearTimeout(this.auth_message_timeout_handle);
      this.auth_message_timeout_handle = null;
    }

    await this.sendMessage({
      message: {
        message_type: 'auth_result',
        state: 'authenticated',
        privileges: auth_result.privileges
      }
    });
  }

  private async handleRequest(params: {
    message: transport_request_message_t;
  }): Promise<void> {
    const request = params.message.request;

    if (!request || typeof request !== 'object') {
      await this.sendResponse({
        response: {
          request_id: 'unknown',
          state: 'error',
          error: CreateRemoteError({
            code: 'invalid_request',
            message: 'request must be an object.'
          })
        }
      });
      return;
    }

    const request_id =
      typeof request.request_id === 'string' && request.request_id.length > 0
        ? request.request_id
        : 'unknown';

    if (
      request.operation !== 'invoke_function' &&
      request.operation !== 'define_function' &&
      request.operation !== 'undefine_function' &&
      request.operation !== 'define_constant' &&
      request.operation !== 'undefine_constant' &&
      request.operation !== 'define_dependency' &&
      request.operation !== 'undefine_dependency'
    ) {
      await this.sendResponse({
        response: {
          request_id,
          state: 'error',
          error: CreateRemoteError({
            code: 'invalid_operation',
            message: 'operation is unsupported.'
          })
        }
      });
      return;
    }

    const required_privilege = RequiredPrivilegeForOperation({ operation: request.operation });
    if (!HasPrivilege({ auth_state: this.auth_state, required_privilege })) {
      await this.sendResponse({
        response: {
          request_id,
          state: 'error',
          error: CreateRemoteError({
            code: 'insufficient_privileges',
            message: `Operation "${request.operation}" requires privilege "${required_privilege}".`
          })
        }
      });
      return;
    }

    if (!this.authenticated_api_key) {
      await this.sendResponse({
        response: {
          request_id,
          state: 'error',
          error: CreateRemoteError({
            code: 'not_authenticated',
            message: 'Authenticated API key context is missing.'
          })
        }
      });
      return;
    }

    if (this.in_flight_request_count >= this.max_in_flight_requests_per_connection) {
      this.abuse_controller.onInFlightRateLimited();
      await this.sendResponse({
        response: {
          request_id,
          state: 'error',
          error: CreateRemoteError({
            code: 'rate_limited',
            message: 'Too many in-flight requests for this connection.',
            details: {
              retry_after_ms: 50,
              scope: 'in_flight_per_connection'
            }
          })
        }
      });
      return;
    }

    const per_connection_limit_result = this.per_connection_request_rate_limiter.consume({});
    if (!per_connection_limit_result.allowed) {
      this.abuse_controller.onPerConnectionRateLimited();
      await this.sendResponse({
        response: {
          request_id,
          state: 'error',
          error: CreateRemoteError({
            code: 'rate_limited',
            message: 'Per-connection request rate limit exceeded.',
            details: {
              retry_after_ms: per_connection_limit_result.retry_after_ms,
              scope: 'per_connection'
            }
          })
        }
      });

      if (this.abuse_controller.getControls().request_controls.per_connection.disconnect_on_limit) {
        this.safeDestroy({ reason: 'per_connection_rate_limited' });
      }
      return;
    }

    const shared_limit_result = this.abuse_controller.evaluateSharedRequestRateLimit({
      remote_address: this.remote_address,
      api_key: this.authenticated_api_key
    });
    if (!shared_limit_result.allowed) {
      await this.sendResponse({
        response: {
          request_id,
          state: 'error',
          error: CreateRemoteError({
            code: shared_limit_result.code,
            message: shared_limit_result.message,
            details: {
              retry_after_ms: shared_limit_result.retry_after_ms,
              ...(shared_limit_result.details ?? {})
            }
          })
        }
      });

      if (shared_limit_result.disconnect_on_limit) {
        this.safeDestroy({ reason: 'shared_rate_limited' });
      }
      return;
    }

    this.in_flight_request_count += 1;
    try {
      const result = await RunWithTimeout({
        timeout_ms: this.request_timeout_ms,
        timeout_message: `Operation "${request.operation}" exceeded request_timeout_ms.`,
        callback: async () => {
          return await this.executeOperation({ request });
        }
      });

      await this.sendResponse({
        response: {
          request_id,
          state: 'ok',
          result
        }
      });
    } catch (error) {
      await this.sendResponse({
        response: {
          request_id,
          state: 'error',
          error: CreateRemoteError({
            code: 'operation_failed',
            message: GetErrorMessage({ error })
          })
        }
      });
    } finally {
      this.in_flight_request_count = Math.max(0, this.in_flight_request_count - 1);
    }
  }

  private async executeOperation(params: { request: networkprocedurecall_request_t }): Promise<unknown> {
    const { request } = params;

    if (request.operation === 'invoke_function') {
      const payload = NormalizeRemoteInvokePayload({ payload: request.payload });
      const call_proxy = this.workerprocedurecall.call as Record<string, unknown>;
      const callable_target = call_proxy[payload.function_name];

      if (typeof callable_target !== 'function') {
        throw new Error(`Remote worker function "${payload.function_name}" does not exist.`);
      }

      return await (callable_target as (...args: unknown[]) => Promise<unknown>)(
        ...payload.call_args
      );
    }

    if (request.operation === 'define_function') {
      const payload = NormalizeRemoteDefineFunctionPayload({ payload: request.payload });
      const expected_hash = HashFunctionSourceSha256({
        function_source: payload.function_source
      });

      if (expected_hash !== payload.source_hash_sha256) {
        throw new Error('define_function payload hash mismatch.');
      }

      const compiled_function = CompileRemoteFunction({
        function_source: payload.function_source
      });

      const define_params: define_worker_function_params_t = {
        name: payload.name,
        worker_func: compiled_function
      };

      await this.workerprocedurecall.defineWorkerFunction(define_params);
      return null;
    }

    if (request.operation === 'undefine_function') {
      const payload = NormalizeRemoteUndefineFunctionPayload({ payload: request.payload });
      await this.workerprocedurecall.undefineWorkerFunction({ name: payload.name });
      return null;
    }

    if (request.operation === 'define_constant') {
      const payload = NormalizeRemoteDefineConstantPayload({ payload: request.payload });
      await this.workerprocedurecall.defineWorkerConstant({
        name: payload.name,
        value: payload.value
      });
      return null;
    }

    if (request.operation === 'undefine_constant') {
      const payload = NormalizeRemoteUndefineConstantPayload({ payload: request.payload });
      await this.workerprocedurecall.undefineWorkerConstant({
        name: payload.name
      });
      return null;
    }

    if (request.operation === 'define_dependency') {
      const payload = NormalizeRemoteDefineDependencyPayload({ payload: request.payload });

      const define_dependency_params: define_worker_dependency_params_t = {
        alias: payload.alias,
        module_specifier: payload.module_specifier
      };

      if (typeof payload.export_name === 'string') {
        define_dependency_params.export_name = payload.export_name;
      }

      if (typeof payload.is_default_export === 'boolean') {
        define_dependency_params.is_default_export = payload.is_default_export;
      }

      await this.workerprocedurecall.defineWorkerDependency(define_dependency_params);
      return null;
    }

    const payload = NormalizeRemoteUndefineDependencyPayload({ payload: request.payload });
    await this.workerprocedurecall.undefineWorkerDependency({
      alias: payload.alias
    });
    return null;
  }

  private async sendResponse(params: { response: networkprocedurecall_response_t }): Promise<void> {
    await this.sendMessage({
      message: {
        message_type: 'response',
        response: params.response
      }
    });
  }

  private async sendMessage(params: { message: transport_message_t }): Promise<void> {
    const outbound_max_frame_bytes = this.auth_state.is_authenticated
      ? this.max_post_auth_frame_bytes
      : this.max_pre_auth_frame_bytes;

    const frame = SerializeLengthPrefixedFrame({
      payload: params.message,
      max_frame_bytes: outbound_max_frame_bytes
    });
    this.socket.write(frame);
  }

  private buildAuthCallbackParams(params: {
    api_key: string;
  }): Parameters<networkprocedurecall_auth_callback_t>[0] {
    const auth_callback_params: Parameters<networkprocedurecall_auth_callback_t>[0] = {
      api_key: params.api_key,
      remote_address: this.remote_address
    };

    const peer_certificate = this.socket.getPeerCertificate();
    if (!peer_certificate || Object.keys(peer_certificate).length === 0) {
      return auth_callback_params;
    }

    auth_callback_params.tls_peer_subject = JSON.stringify(peer_certificate.subject ?? {});
    auth_callback_params.tls_peer_san =
      typeof peer_certificate.subjectaltname === 'string'
        ? peer_certificate.subjectaltname
        : undefined;
    auth_callback_params.tls_peer_fingerprint256 =
      typeof peer_certificate.fingerprint256 === 'string'
        ? peer_certificate.fingerprint256
        : undefined;
    auth_callback_params.tls_peer_serial_number =
      typeof peer_certificate.serialNumber === 'string'
        ? peer_certificate.serialNumber
        : undefined;

    return auth_callback_params;
  }

  private releaseUnauthenticatedSessionTracking(): void {
    if (!this.is_unauthenticated_session_tracked) {
      return;
    }

    this.is_unauthenticated_session_tracked = false;
    this.abuse_controller.releaseUnauthenticatedSession();
  }

  private safeDestroy(params: { reason: string }): void {
    if (this.lifecycle_state === 'closed') {
      return;
    }

    if (this.auth_message_timeout_handle) {
      clearTimeout(this.auth_message_timeout_handle);
      this.auth_message_timeout_handle = null;
    }

    this.lifecycle_state = 'closed';
    this.socket.destroy(new Error(params.reason));
  }
}

class NetworkProcedureCallClientSession implements networkprocedurecall_client_session_i {
  private readonly server_name: string;
  private readonly server_definition: normalized_client_server_definition_t;

  private socket: tls.TLSSocket | null = null;
  private frame_reader: LengthPrefixedFrameReader | null = null;

  private connect_promise: Promise<void> | null = null;
  private is_connected = false;
  private is_authenticated = false;
  private is_closed = false;

  private pending_request_by_id = new Map<string, pending_request_t>();
  private next_request_id = 1;

  private pending_messages: transport_message_t[] = [];
  private waiters: pending_waiter_t[] = [];

  private pending_ping_by_id = new Map<
    string,
    {
      resolve: () => void;
      reject: (error: Error) => void;
      timeout_handle: NodeJS.Timeout;
    }
  >();

  constructor(params: { server_name: string; server_definition: networkprocedurecall_client_server_definition_t }) {
    this.server_name = params.server_name;
    this.server_definition = NormalizeClientServerDefinition({
      server_definition: params.server_definition
    });
  }

  async connect(): Promise<void> {
    if (this.is_authenticated && this.is_connected) {
      return;
    }

    if (this.connect_promise) {
      await this.connect_promise;
      return;
    }

    this.connect_promise = this.connectInternal();
    try {
      await this.connect_promise;
    } finally {
      this.connect_promise = null;
    }
  }

  async disconnect(): Promise<void> {
    if (this.is_closed) {
      return;
    }

    this.is_closed = true;
    this.is_connected = false;
    this.is_authenticated = false;

    for (const pending_request of this.pending_request_by_id.values()) {
      clearTimeout(pending_request.timeout_handle);
      pending_request.reject(new Error(`Connection to server "${this.server_name}" was closed.`));
    }
    this.pending_request_by_id.clear();

    for (const waiter of this.waiters) {
      clearTimeout(waiter.timeout_handle);
      waiter.reject(new Error(`Connection to server "${this.server_name}" was closed.`));
    }
    this.waiters = [];

    for (const pending_ping of this.pending_ping_by_id.values()) {
      clearTimeout(pending_ping.timeout_handle);
      pending_ping.reject(new Error(`Connection to server "${this.server_name}" was closed.`));
    }
    this.pending_ping_by_id.clear();

    if (this.socket) {
      this.socket.destroy();
    }

    this.socket = null;
    this.frame_reader = null;
    this.pending_messages = [];
  }

  async invokeFunction(params: {
    function_name: string;
    call_args: unknown[];
  }): Promise<unknown> {
    return await this.sendRequest({
      operation: 'invoke_function',
      payload: {
        function_name: params.function_name,
        call_args: params.call_args
      }
    });
  }

  async defineFunction(params: remote_define_function_input_t): Promise<void> {
    const normalized_payload = NormalizeRemoteDefineFunctionInput({
      define_function_input: params
    });

    await this.sendRequest({
      operation: 'define_function',
      payload: normalized_payload
    });
  }

  async undefineFunction(params: remote_undefine_function_payload_t): Promise<void> {
    await this.sendRequest({
      operation: 'undefine_function',
      payload: params
    });
  }

  async defineConstant(params: remote_define_constant_payload_t): Promise<void> {
    await this.sendRequest({
      operation: 'define_constant',
      payload: params
    });
  }

  async undefineConstant(params: remote_undefine_constant_payload_t): Promise<void> {
    await this.sendRequest({
      operation: 'undefine_constant',
      payload: params
    });
  }

  async defineDependency(params: remote_define_dependency_payload_t): Promise<void> {
    await this.sendRequest({
      operation: 'define_dependency',
      payload: params
    });
  }

  async undefineDependency(params: remote_undefine_dependency_payload_t): Promise<void> {
    await this.sendRequest({
      operation: 'undefine_dependency',
      payload: params
    });
  }

  async ping(): Promise<void> {
    await this.connect();

    const ping_id = `ping_${crypto.randomUUID()}`;
    await this.sendMessage({
      message: {
        message_type: 'ping',
        ping_id
      }
    });

    const ping_timeout_handle = setTimeout(() => {
      const pending_ping = this.pending_ping_by_id.get(ping_id);
      if (!pending_ping) {
        return;
      }

      this.pending_ping_by_id.delete(ping_id);
      pending_ping.reject(
        new Error(
          `Ping timeout for server "${this.server_name}" after ${this.getRequestTimeoutMs()}ms.`
        )
      );
    }, this.getRequestTimeoutMs());

    await new Promise<void>((resolve, reject) => {
      this.pending_ping_by_id.set(ping_id, {
        resolve: () => {
          clearTimeout(ping_timeout_handle);
          resolve();
        },
        reject: (error: Error) => {
          clearTimeout(ping_timeout_handle);
          reject(error);
        },
        timeout_handle: ping_timeout_handle
      });
    });
  }

  private async connectInternal(): Promise<void> {
    this.is_closed = false;

    await new Promise<void>((resolve, reject) => {
      const tls_socket = tls.connect({
        host: this.server_definition.network.host,
        port: this.server_definition.network.tcp_remote_port,
        key: this.server_definition.tls_mtls.key_pem,
        cert: this.server_definition.tls_mtls.cert_pem,
        ca: this.server_definition.tls_mtls.ca_pem,
        crl: this.server_definition.tls_mtls.crl_pem ?? undefined,
        minVersion: this.server_definition.tls_mtls.min_version,
        ciphers: this.server_definition.tls_mtls.cipher_suites ?? undefined,
        servername: this.server_definition.tls_mtls.servername,
        rejectUnauthorized: true
      });

      tls_socket.setNoDelay(true);
      tls_socket.setTimeout(this.getHandshakeTimeoutMs());

      let settled = false;
      const finalize = (params: {
        error?: Error;
      }): void => {
        if (settled) {
          return;
        }
        settled = true;
        tls_socket.removeAllListeners('error');
        tls_socket.removeAllListeners('secureConnect');
        tls_socket.removeAllListeners('close');
        tls_socket.removeAllListeners('timeout');

        if (params.error) {
          reject(params.error);
          return;
        }
        resolve();
      };

      tls_socket.once('secureConnect', () => {
        if (!tls_socket.authorized) {
          finalize({
            error: new Error(String(tls_socket.authorizationError ?? 'mTLS peer authorization failed.'))
          });
          return;
        }

        finalize({});
      });

      tls_socket.once('error', (error) => {
        finalize({
          error: error instanceof Error ? error : new Error(String(error))
        });
      });

      tls_socket.once('timeout', () => {
        finalize({
          error: new Error('mTLS client handshake timed out before secureConnect.')
        });
      });

      tls_socket.once('close', () => {
        finalize({
          error: new Error('Socket closed before mTLS secureConnect completed.')
        });
      });

      this.socket = tls_socket;
    });

    const socket = this.requireSocket();

    this.frame_reader = new LengthPrefixedFrameReader(
      this.getMaxFrameBytes(),
      ({ frame }) => {
        this.handleFrame({ frame });
      },
      ({ error: _error }) => {
        void this.disconnect();
      }
    );

    socket.removeAllListeners('error');

    socket.on('data', (chunk: Buffer) => {
      this.frame_reader?.pushData({ chunk });
    });

    socket.on('timeout', () => {
      void this.disconnect();
    });

    socket.on('error', () => {
      void this.disconnect();
    });

    socket.on('close', () => {
      void this.disconnect();
    });

    await this.performAuthentication();

    socket.setTimeout(0);
    this.is_connected = true;
    this.is_authenticated = true;
  }

  private async performAuthentication(): Promise<void> {
    await this.sendMessage({
      message: {
        message_type: 'auth',
        api_key: this.server_definition.authentication.api_key
      }
    });

    const auth_message = await this.waitForMessage({
      timeout_ms: this.getRequestTimeoutMs()
    });

    if (auth_message.message_type === 'error') {
      throw new RemoteRequestError({
        code: auth_message.error.code,
        message: auth_message.error.message,
        details: auth_message.error.details
      });
    }

    if (!auth_message || auth_message.message_type !== 'auth_result') {
      throw new Error('Expected auth_result message after auth request.');
    }

    if (auth_message.state !== 'authenticated') {
      throw new Error('Authentication failed for provided API key.');
    }
  }

  private handleFrame(params: { frame: Buffer }): void {
    let message: transport_message_t;
    try {
      message = ParseJsonFrame({ frame: params.frame }) as transport_message_t;
    } catch {
      void this.disconnect();
      return;
    }

    if (message.message_type === 'response') {
      this.resolvePendingRequest({ response_message: message });
      return;
    }

    if (message.message_type === 'pong') {
      const pending_ping = this.pending_ping_by_id.get(message.ping_id);
      if (pending_ping) {
        this.pending_ping_by_id.delete(message.ping_id);
        pending_ping.resolve();
      }
      return;
    }

    this.queueMessage({ message });
  }

  private resolvePendingRequest(params: { response_message: transport_response_message_t }): void {
    const pending_request = this.pending_request_by_id.get(params.response_message.response.request_id);
    if (!pending_request) {
      return;
    }

    this.pending_request_by_id.delete(params.response_message.response.request_id);
    clearTimeout(pending_request.timeout_handle);

    if (params.response_message.response.state === 'ok') {
      pending_request.resolve(params.response_message.response.result);
      return;
    }

    const remote_error = params.response_message.response.error;
    pending_request.reject(
      new RemoteRequestError({
        code: remote_error?.code ?? 'remote_error',
        message: remote_error?.message ?? 'Remote operation failed.',
        details: remote_error?.details
      })
    );
  }

  private queueMessage(params: { message: transport_message_t }): void {
    if (this.waiters.length > 0) {
      const waiter = this.waiters.shift();
      if (waiter) {
        clearTimeout(waiter.timeout_handle);
        waiter.resolve(params.message);
      }
      return;
    }

    this.pending_messages.push(params.message);
  }

  private async waitForMessage(params: { timeout_ms: number }): Promise<transport_message_t> {
    if (this.pending_messages.length > 0) {
      return this.pending_messages.shift() as transport_message_t;
    }

    return await new Promise<transport_message_t>((resolve, reject) => {
      const timeout_handle = setTimeout(() => {
        reject(new Error('Timeout while waiting for transport message.'));
      }, params.timeout_ms);

      this.waiters.push({
        resolve: (message) => {
          resolve(message as transport_message_t);
        },
        reject,
        timeout_handle
      });
    });
  }

  private async sendRequest(params: {
    operation: networkprocedurecall_operation_name_t;
    payload: networkprocedurecall_request_payload_t;
  }): Promise<unknown> {
    await this.connect();

    const request_id = `req_${this.next_request_id}`;
    this.next_request_id += 1;

    await this.sendMessage({
      message: {
        message_type: 'request',
        request: {
          request_id,
          operation: params.operation,
          payload: params.payload
        }
      }
    });

    return await new Promise<unknown>((resolve, reject) => {
      const timeout_handle = setTimeout(() => {
        this.pending_request_by_id.delete(request_id);
        reject(
          new Error(
            `Request timeout for operation "${params.operation}" after ${this.getRequestTimeoutMs()}ms.`
          )
        );
      }, this.getRequestTimeoutMs());

      this.pending_request_by_id.set(request_id, {
        resolve,
        reject,
        timeout_handle
      });
    });
  }

  private async sendMessage(params: { message: transport_message_t }): Promise<void> {
    const socket = this.requireSocket();
    const frame = SerializeLengthPrefixedFrame({
      payload: params.message,
      max_frame_bytes: this.getMaxFrameBytes()
    });
    socket.write(frame);
  }

  private getHandshakeTimeoutMs(): number {
    return this.server_definition.tls_mtls.handshake_timeout_ms;
  }

  private getRequestTimeoutMs(): number {
    return this.server_definition.tls_mtls.request_timeout_ms;
  }

  private getMaxFrameBytes(): number {
    return this.server_definition.tls_mtls.max_frame_bytes;
  }

  private requireSocket(): tls.TLSSocket {
    if (!this.socket) {
      throw new Error('Socket is not initialized.');
    }

    return this.socket;
  }
}

export class NetworkProcedureCall {
  private readonly workerprocedurecall: WorkerProcedureCall;

  private server: tls.Server | null = null;
  private server_start_params: networkprocedurecall_server_start_params_t | null = null;
  private normalized_tls_mtls_params: normalized_tls_mtls_params_t | null = null;
  private abuse_controller: NetworkProcedureCallAbuseController | null = null;
  private server_sessions = new Set<networkprocedurecall_server_session_i>();
  private readonly raw_socket_state_by_socket_key = new Map<string, raw_socket_state_t>();

  constructor(params: networkprocedurecall_constructor_params_t) {
    this.workerprocedurecall = params.workerprocedurecall;
  }

  async start(params: networkprocedurecall_server_start_params_t): Promise<void> {
    if (this.server) {
      throw new Error('NetworkProcedureCall server is already started.');
    }

    AssertPositiveInteger({
      value: params.network.tcp_listen_port,
      label: 'tcp_listen_port'
    });

    if (params.network.bind_addr.length === 0) {
      throw new Error('bind_addr must be a non-empty string.');
    }

    if (params.information.server_name.length === 0) {
      throw new Error('information.server_name must be a non-empty string.');
    }

    this.server_start_params = params;
    this.normalized_tls_mtls_params = NormalizeTlsMtlsParams({
      tls_mtls: params.tls_mtls,
      require_servername: false
    });
    this.abuse_controller = new NetworkProcedureCallAbuseController(
      NormalizeAbuseControls({
        abuse_controls: params.abuse_controls,
        max_frame_bytes: this.normalized_tls_mtls_params.max_frame_bytes
      })
    );

    const server = tls.createServer(
      {
        key: this.normalized_tls_mtls_params.key_pem,
        cert: this.normalized_tls_mtls_params.cert_pem,
        ca: this.normalized_tls_mtls_params.ca_pem,
        crl: this.normalized_tls_mtls_params.crl_pem ?? undefined,
        minVersion: this.normalized_tls_mtls_params.min_version,
        ciphers: this.normalized_tls_mtls_params.cipher_suites ?? undefined,
        requestCert: true,
        rejectUnauthorized: true,
        handshakeTimeout: this.abuse_controller.getControls().connection_controls.tls_handshake_timeout_ms
      },
      (socket) => {
        this.handleSocketConnection({ socket });
      }
    );

    server.on('connection', (raw_socket) => {
      this.handleRawConnection({ raw_socket });
    });

    await new Promise<void>((resolve, reject) => {
      server.once('error', (error) => {
        reject(error);
      });

      server.listen(params.network.tcp_listen_port, params.network.bind_addr, () => {
        resolve();
      });
    });

    this.server = server;

    this.server.on('error', () => {
      void this.stop();
    });
  }

  async stop(): Promise<void> {
    const active_server = this.server;
    this.server = null;
    this.raw_socket_state_by_socket_key.clear();

    await Promise.all(
      Array.from(this.server_sessions.values()).map(async (server_session) => {
        await server_session.close();
      })
    );

    this.server_sessions.clear();
    this.server_start_params = null;
    this.normalized_tls_mtls_params = null;
    this.abuse_controller = null;

    if (!active_server) {
      return;
    }

    await new Promise<void>((resolve) => {
      active_server.close(() => {
        resolve();
      });
    });
  }

  getWorkerProcedureCall(): WorkerProcedureCall {
    return this.workerprocedurecall;
  }

  getAbuseMetrics(): networkprocedurecall_abuse_metrics_t {
    if (!this.abuse_controller) {
      return CloneAbuseMetrics({
        abuse_metrics: DEFAULT_ABUSE_METRICS
      });
    }

    return this.abuse_controller.getMetrics();
  }

  private handleRawConnection(params: { raw_socket: net.Socket }): void {
    const abuse_controller = this.abuse_controller;
    if (!abuse_controller) {
      params.raw_socket.destroy();
      return;
    }

    const remote_address = params.raw_socket.remoteAddress ?? 'unknown';
    const admission_decision = abuse_controller.onRawConnectionOpenAttempt({
      remote_address
    });
    const socket_key = BuildSocketKey({
      socket: params.raw_socket
    });

    const raw_socket_state: raw_socket_state_t = {
      is_tracked_connection: admission_decision.allowed,
      is_handshake_in_progress: admission_decision.allowed
    };
    this.raw_socket_state_by_socket_key.set(socket_key, raw_socket_state);

    params.raw_socket.setTimeout(
      abuse_controller.getControls().connection_controls.tls_handshake_timeout_ms
    );
    params.raw_socket.on('timeout', () => {
      const socket_state = this.raw_socket_state_by_socket_key.get(socket_key);
      if (socket_state) {
        socket_state.close_reason = 'tls_handshake_timeout';
      }
      params.raw_socket.destroy(new Error('tls_handshake_timeout'));
    });

    params.raw_socket.on('close', () => {
      const socket_state = this.raw_socket_state_by_socket_key.get(socket_key);
      this.raw_socket_state_by_socket_key.delete(socket_key);

      if (!socket_state) {
        return;
      }

      abuse_controller.onRawConnectionClosed({
        was_tracked_connection: socket_state.is_tracked_connection,
        was_handshake_in_progress: socket_state.is_handshake_in_progress,
        close_reason: socket_state.close_reason
      });
    });

    if (!admission_decision.allowed) {
      abuse_controller.log({
        message: `connection rejected from ${remote_address} (${admission_decision.code})`
      });
      params.raw_socket.destroy(new Error(admission_decision.message));
    }
  }

  private handleSocketConnection(params: { socket: tls.TLSSocket }): void {
    const tls_mtls_params = this.normalized_tls_mtls_params;
    const start_params = this.server_start_params;
    const abuse_controller = this.abuse_controller;

    if (!tls_mtls_params || !start_params || !abuse_controller) {
      params.socket.destroy();
      return;
    }

    const socket_key = BuildSocketKey({
      socket: params.socket
    });
    const raw_socket_state = this.raw_socket_state_by_socket_key.get(socket_key);
    if (raw_socket_state && raw_socket_state.is_handshake_in_progress) {
      raw_socket_state.is_handshake_in_progress = false;
      const tls_handshake_decision = abuse_controller.onTlsHandshakeFinished();
      if (!tls_handshake_decision.allowed) {
        params.socket.destroy(new Error(tls_handshake_decision.message));
        return;
      }
    }

    if (!params.socket.authorized) {
      abuse_controller.onHandshakeAuthorizationFailure();
      params.socket.destroy(
        new Error(String(params.socket.authorizationError ?? 'mTLS peer authorization failed.'))
      );
      return;
    }

    const server_session = new NetworkProcedureCallServerSession({
      workerprocedurecall: this.workerprocedurecall,
      socket: params.socket,
      auth_callback: start_params.auth_callback,
      tls_mtls: tls_mtls_params,
      abuse_controller,
      on_close: ({ session }) => {
        this.server_sessions.delete(session);
      }
    });

    this.server_sessions.add(server_session);
  }
}

export class NetworkProcedureCallClient {
  [server_name: string]: any;
  public readonly all_servers: networkprocedurecall_client_all_servers_methods_t;

  private readonly server_session_by_name = new Map<string, networkprocedurecall_client_session_i>();

  constructor(params: networkprocedurecall_client_constructor_params_t) {
    for (const [server_name, server_definition] of Object.entries(params.servers)) {
      if (server_name.length === 0) {
        throw new Error('servers map cannot contain empty server_name keys.');
      }
      if (server_name === 'all_servers') {
        throw new Error('servers map cannot contain reserved server_name "all_servers".');
      }

      const client_session = new NetworkProcedureCallClientSession({
        server_name,
        server_definition
      });
      this.server_session_by_name.set(server_name, client_session);

      Object.defineProperty(this, server_name, {
        enumerable: true,
        configurable: false,
        writable: false,
        value: this.createServerMethodFacade({
          client_session
        })
      });
    }

    const all_servers_methods = this.createAllServersMethodFacade();
    this.all_servers = all_servers_methods;
    Object.defineProperty(this, 'all_servers', {
      enumerable: true,
      configurable: false,
      writable: false,
      value: all_servers_methods
    });
  }

  async disconnectAll(): Promise<void> {
    for (const client_session of this.server_session_by_name.values()) {
      await client_session.disconnect();
    }
  }

  private createServerMethodFacade(params: {
    client_session: networkprocedurecall_client_session_i;
  }): networkprocedurecall_client_server_methods_t {
    const call_proxy_target: Record<string, unknown> = {};

    const call_proxy = new Proxy(call_proxy_target, {
      get: (_target, property_name: string | symbol): unknown => {
        if (typeof property_name !== 'string') {
          return undefined;
        }

        if (
          property_name === 'then' ||
          property_name === 'catch' ||
          property_name === 'finally'
        ) {
          return undefined;
        }

        return async (...call_args: unknown[]): Promise<unknown> => {
          return await params.client_session.invokeFunction({
            function_name: property_name,
            call_args
          });
        };
      }
    });

    return {
      call: call_proxy as networkprocedurecall_client_server_call_proxy_t,
      ping: async (): Promise<void> => {
        await params.client_session.ping();
      },
      defineFunction: async (define_function_params): Promise<void> => {
        await params.client_session.defineFunction(define_function_params);
      },
      undefineFunction: async (undefine_function_params): Promise<void> => {
        await params.client_session.undefineFunction(undefine_function_params);
      },
      defineConstant: async (define_constant_params): Promise<void> => {
        await params.client_session.defineConstant(define_constant_params);
      },
      undefineConstant: async (undefine_constant_params): Promise<void> => {
        await params.client_session.undefineConstant(undefine_constant_params);
      },
      defineDependency: async (define_dependency_params): Promise<void> => {
        await params.client_session.defineDependency(define_dependency_params);
      },
      undefineDependency: async (undefine_dependency_params): Promise<void> => {
        await params.client_session.undefineDependency(undefine_dependency_params);
      },
      disconnect: async (): Promise<void> => {
        await params.client_session.disconnect();
      }
    };
  }

  private createAllServersMethodFacade(): networkprocedurecall_client_all_servers_methods_t {
    const call_proxy_target: Record<string, unknown> = {};

    const call_proxy = new Proxy(call_proxy_target, {
      get: (_target, property_name: string | symbol): unknown => {
        if (typeof property_name !== 'string') {
          return undefined;
        }

        if (
          property_name === 'then' ||
          property_name === 'catch' ||
          property_name === 'finally'
        ) {
          return undefined;
        }

        return async (...call_args: unknown[]): Promise<all_servers_operation_result_map_t<unknown>> => {
          return await this.executeAcrossAllServers({
            operation: async ({ client_session }) => {
              return await client_session.invokeFunction({
                function_name: property_name,
                call_args
              });
            }
          });
        };
      }
    });

    return {
      call: call_proxy as networkprocedurecall_client_all_servers_call_proxy_t,
      ping: async (): Promise<all_servers_operation_result_map_t<null>> => {
        return await this.executeAcrossAllServers({
          operation: async ({ client_session }) => {
            await client_session.ping();
            return null;
          }
        });
      },
      defineFunction: async (
        define_function_params
      ): Promise<all_servers_operation_result_map_t<null>> => {
        return await this.executeAcrossAllServers({
          operation: async ({ client_session }) => {
            await client_session.defineFunction(define_function_params);
            return null;
          }
        });
      },
      undefineFunction: async (
        undefine_function_params
      ): Promise<all_servers_operation_result_map_t<null>> => {
        return await this.executeAcrossAllServers({
          operation: async ({ client_session }) => {
            await client_session.undefineFunction(undefine_function_params);
            return null;
          }
        });
      },
      defineConstant: async (
        define_constant_params
      ): Promise<all_servers_operation_result_map_t<null>> => {
        return await this.executeAcrossAllServers({
          operation: async ({ client_session }) => {
            await client_session.defineConstant(define_constant_params);
            return null;
          }
        });
      },
      undefineConstant: async (
        undefine_constant_params
      ): Promise<all_servers_operation_result_map_t<null>> => {
        return await this.executeAcrossAllServers({
          operation: async ({ client_session }) => {
            await client_session.undefineConstant(undefine_constant_params);
            return null;
          }
        });
      },
      defineDependency: async (
        define_dependency_params
      ): Promise<all_servers_operation_result_map_t<null>> => {
        return await this.executeAcrossAllServers({
          operation: async ({ client_session }) => {
            await client_session.defineDependency(define_dependency_params);
            return null;
          }
        });
      },
      undefineDependency: async (
        undefine_dependency_params
      ): Promise<all_servers_operation_result_map_t<null>> => {
        return await this.executeAcrossAllServers({
          operation: async ({ client_session }) => {
            await client_session.undefineDependency(undefine_dependency_params);
            return null;
          }
        });
      },
      disconnect: async (): Promise<all_servers_operation_result_map_t<null>> => {
        return await this.executeAcrossAllServers({
          operation: async ({ client_session }) => {
            await client_session.disconnect();
            return null;
          }
        });
      }
    };
  }

  private async executeAcrossAllServers<result_t>(params: {
    operation: (params: {
      server_name: string;
      client_session: networkprocedurecall_client_session_i;
    }) => Promise<result_t>;
  }): Promise<all_servers_operation_result_map_t<result_t>> {
    const operation_results = await Promise.all(
      Array.from(this.server_session_by_name.entries()).map(async ([server_name, client_session]) => {
        try {
          const operation_result = await params.operation({
            server_name,
            client_session
          });
          return [
            server_name,
            {
              state: 'ok',
              result: operation_result
            }
          ] as const;
        } catch (error) {
          return [
            server_name,
            {
              state: 'error',
              error: this.normalizeAllServersError({ error })
            }
          ] as const;
        }
      })
    );

    const result_map: all_servers_operation_result_map_t<result_t> = {};
    for (const [server_name, operation_result] of operation_results) {
      result_map[server_name] = operation_result;
    }

    return result_map;
  }

  private normalizeAllServersError(params: {
    error: unknown;
  }): networkprocedurecall_remote_error_t {
    if (params.error instanceof RemoteRequestError) {
      return CreateRemoteError({
        code: params.error.code,
        message: params.error.message,
        details: params.error.details
      });
    }

    if (params.error instanceof Error) {
      if (params.error.message.includes('Authentication failed')) {
        return CreateRemoteError({
          code: 'authentication_failed',
          message: params.error.message
        });
      }

      return CreateRemoteError({
        code: 'client_error',
        message: params.error.message
      });
    }

    return CreateRemoteError({
      code: 'unknown_error',
      message: GetErrorMessage({ error: params.error }),
      details: params.error
    });
  }
}

export function CreateRemoteFunctionPayload(params: {
  name: string;
  function_source: string;
}): remote_define_function_payload_t {
  if (params.name.length === 0) {
    throw new Error('name must be a non-empty string.');
  }
  if (params.function_source.length === 0) {
    throw new Error('function_source must be a non-empty string.');
  }

  return {
    name: params.name,
    function_source: params.function_source,
    source_hash_sha256: HashFunctionSourceSha256({
      function_source: params.function_source
    })
  };
}
