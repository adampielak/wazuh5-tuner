#!/usr/bin/env python3
"""Wazuh 5 manager wazuh-manager-internal-options.conf tuning UI and checker.

Every key, default and range below comes from the Wazuh v5.0.0-rc2 source,
cross-checked against the rc2 documentation (see README.md and data/params.json
for the exact source and doc locations). tools/build-params.ts writes the
PARAMS block; do not edit it by hand.

Two parsers read the same file:
  * C daemons (remoted, wazuh-db, authd, modulesd): the FIRST matching line
    wins, lines starting with '#', ' ' or a newline are skipped, the value is
    digits with an optional leading '-', nothing else (no inline comment, no
    trailing space). A bad value stops the daemon at start.
  * Engine (wazuh-manager-analysisd, analysisd.* keys): the LAST matching line
    wins, an unescaped '#' ends the value, quotes are stripped, booleans are
    true/false. A bad value stops the engine at start.

Run:   python3 wazuh5-tuner.py [--host 127.0.0.1] [--port 7438]
Check: python3 wazuh5-tuner.py --check /etc/wazuh-manager/wazuh-manager-internal-options.conf
"""
import argparse
import json
import re
import socketserver
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WAZUH_VERSION = "5.0.0-rc2"
TARGET = "/etc/wazuh-manager/wazuh-manager-internal-options.conf"
INT_MIN, INT_MAX = -2147483648, 2147483647
# std::from_chars bounds for engine keys without a range of their own (params "tuner_cap").
ENGINE_TYPE_BOUNDS = {"int": (INT_MIN, INT_MAX), "int64_t": (-2**63, 2**63 - 1), "size_t": (0, 2**64 - 1)}
C_LINE_MAX = 1023       # the C reader uses fgets() into a 1024-byte buffer

# BEGIN PARAMS (written by tools/build-params.ts, do not edit by hand)
PARAMS = json.loads(r"""{
 "engine": {"label": "Engine (wazuh-manager-analysisd)", "desc": "Event queue, orchestrator, indexer output, content sync and stream logs. analysisd.* keys: the LAST line wins, an inline # ends the value, booleans are true/false.", "params": [
  {"key":"analysisd.agent_metadata_cache_clean_interval","type":"int","default":60,"min":0,"max":9007199254740991,"desc":"Interval in seconds between best-effort evictions of stale agent metadata cache entries.","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.agent_metadata_cache_ttl","type":"int","default":300,"min":1,"max":86400,"desc":"Time-to-live in seconds for cached agent metadata."},
  {"key":"analysisd.api_resource_kvdb_payload_max_bytes","type":"int","default":100000,"min":0,"max":9007199254740991,"desc":"Maximum payload size in bytes accepted for a KVDB resource in the engine's HTTP API server.","note":"tuner range 0 to 2^53-1","tuner_cap":"int64_t"},
  {"key":"analysisd.api_resource_payload_max_bytes","type":"int","default":50000,"min":0,"max":9007199254740991,"desc":"Maximum payload size in bytes accepted for a resource in the engine's HTTP API server.","note":"tuner range 0 to 2^53-1","tuner_cap":"int64_t"},
  {"key":"analysisd.cm_sync_interval","type":"int","default":120,"min":0,"max":9007199254740991,"desc":"Seconds between content synchronization cycles from the Wazuh Indexer.","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.cm_sync_retry_interval","type":"int","default":30,"min":0,"max":3600,"desc":"Seconds until the next content synchronization cycle while a space has no route and its policy is not disabled (the indexer failed, or the content is not ready yet)."},
  {"key":"analysisd.cmsync_indexer_connector_max_retries","type":"int","default":3,"min":0,"max":9007199254740991,"desc":"Maximum retry attempts for content synchronization requests to the Wazuh Indexer.","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.cmsync_indexer_connector_retry_interval","type":"int","default":5,"min":0,"max":9007199254740991,"desc":"Seconds between retry attempts for content synchronization.","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.cmsync_indexer_connector_sync_batch_size","type":"int","default":100,"min":0,"max":9007199254740991,"desc":"Maximum number of content documents requested per Wazuh Indexer page during content synchronization.","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.debug","type":"int","default":0,"min":0,"max":2,"desc":"Log verbosity for the manager-mode engine process: 0 info, 1 debug, 2 (or higher) trace.","note":"no range check in the engine (3 or more also means trace); tuner limits it to 0-2","tuner_cap":"int"},
  {"key":"analysisd.dumper_enabled","type":"bool","default":false,"desc":"Whether the event dumper, which writes every incoming event to the dumper stream log, is active at start-up."},
  {"key":"analysisd.event_queue_eps","type":"int","default":0,"min":0,"max":9007199254740991,"desc":"Maximum number of events per second the router takes from its input queue.","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.event_queue_max_bytes","type":"int","default":33554432,"min":0,"max":9007199254740991,"desc":"Maximum total byte size of events waiting in the router input queue.","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.event_queue_size","type":"int","default":131072,"min":8192,"max":2147483647,"desc":"Maximum number of events waiting in the router input queue."},
  {"key":"analysisd.geo_sync_interval","type":"int","default":360,"min":0,"max":9007199254740991,"desc":"Seconds between GeoIP database synchronization cycles.","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.indexer_bulk_max_bytes","type":"int","default":8388608,"min":65536,"max":104857600,"desc":"Maximum byte size of the bulk payload accumulated before a _bulk request is dispatched to wazuh-indexer."},
  {"key":"analysisd.indexer_flush_interval","type":"int","default":20,"min":1,"max":3600,"desc":"Seconds between periodic flushes of the asynchronous indexer bulk buffer."},
  {"key":"analysisd.indexer_logger_queue_size","type":"int","default":8,"min":1,"max":1024,"desc":"Maximum number of _bulk responses (with their payloads) that can wait in the indexer error-logger queue."},
  {"key":"analysisd.indexer_logger_threads","type":"int","default":1,"min":1,"max":16,"desc":"Number of worker threads that parse _bulk error responses to log per-item failures."},
  {"key":"analysisd.indexer_max_retry_delay","type":"int","default":15,"min":1,"max":3600,"desc":"Maximum exponential-backoff delay in seconds between retries of a failed _bulk request (e.g."},
  {"key":"analysisd.indexer_monitoring_interval","type":"int","default":10,"min":1,"max":3600,"desc":"Polling period in seconds of the indexer health monitor that marks each wazuh-indexer host as available or unavailable for the connector."},
  {"key":"analysisd.indexer_queue_max_bytes","type":"int","default":67108864,"min":0,"max":9007199254740991,"desc":"Maximum number of bytes of events waiting in the indexer output queue.","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.indexer_request_timeout","type":"int","default":60,"min":0,"max":3600,"desc":"Upper bound in seconds for one data request against wazuh-indexer."},
  {"key":"analysisd.ioc_indexer_connector_max_retries","type":"int","default":3,"min":0,"max":9007199254740991,"desc":"Maximum retry attempts for IoC synchronization requests to the Wazuh Indexer.","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.ioc_indexer_connector_retry_interval","type":"int","default":5,"min":0,"max":9007199254740991,"desc":"Seconds between retry attempts for IoC synchronization.","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.ioc_indexer_connector_sync_batch_size","type":"int","default":1000,"min":0,"max":9007199254740991,"desc":"Maximum number of IoC documents streamed per Wazuh Indexer page while synchronizing IoC databases.","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.ioc_sync_interval","type":"int","default":360,"min":0,"max":9007199254740991,"desc":"Seconds between IoC database synchronization cycles.","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.orchestrator_threads","type":"int","default":0,"min":0,"max":128,"desc":"Number of orchestrator worker threads."},
  {"key":"analysisd.remote_conf_indexer_connector_max_retries","type":"int","default":3,"min":0,"max":9007199254740991,"desc":"Maximum retry attempts for remote configuration requests to the Wazuh Indexer.","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.remote_conf_indexer_connector_retry_interval","type":"int","default":5,"min":0,"max":9007199254740991,"desc":"Seconds between retry attempts for remote configuration synchronization.","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.remote_conf_sync_interval","type":"int","default":120,"min":0,"max":9007199254740991,"desc":"Seconds between remote engine configuration synchronization cycles.","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.server_api_payload_max_bytes","type":"int","default":0,"min":0,"max":9007199254740991,"desc":"Maximum request payload size in bytes for the engine's HTTP API server.","note":"tuner range 0 to 2^53-1","tuner_cap":"int64_t"},
  {"key":"analysisd.server_api_timeout","type":"int","default":5000,"min":1,"max":2147483647,"desc":"Tester timeout in milliseconds: how long a test run (/logtest, /_internal/tester/run/post) waits for the event's result before answering 400 with Timeout waiting for ingestTest."},
  {"key":"analysisd.streamlog_compress","type":"bool","default":true,"desc":"Whether rotated stream-log files (events and dumper) are compressed."},
  {"key":"analysisd.streamlog_compression_level","type":"int","default":5,"min":1,"max":9,"desc":"Compression level applied to rotated stream-log files (events and dumper)."},
  {"key":"analysisd.streamlog_dumper_buffer_size","type":"int","default":1048576,"min":0,"max":9007199254740991,"desc":"Capacity, in messages, of the dumper stream log's write queue (0 means the default).","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.streamlog_dumper_max_size","type":"int","default":0,"min":0,"max":9007199254740991,"desc":"Maximum size in bytes of one dumper stream-log file before rotation.","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.streamlog_events_buffer_size","type":"int","default":1048576,"min":0,"max":9007199254740991,"desc":"Capacity, in messages, of the events stream log's write queue (0 means the default).","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.streamlog_events_max_size","type":"int","default":0,"min":0,"max":9007199254740991,"desc":"Maximum size in bytes of one events stream-log file before rotation.","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.streamlog_max_accumulated_size","type":"int","default":21474836480,"min":0,"max":9007199254740991,"desc":"Maximum total disk size of the rotated files in each stream-log channel directory (applied to the events and the dumper channel separately).","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.streamlog_max_files","type":"int","default":90,"min":0,"max":9007199254740991,"desc":"Maximum number of rotated files kept in each stream-log channel directory (applied to the events and the dumper channel separately) before the oldest is deleted.","note":"unsigned, no upper bound in the engine; tuner caps at 2^53-1","tuner_cap":"size_t"},
  {"key":"analysisd.tzdb_auto_update","type":"bool","default":false,"desc":"Whether the engine automatically downloads time-zone database updates."}
 ]},
 "remoted_https": {"label": "Remoted, HTTPS agent server", "desc": "HTTPS transport for 5.x agents (port 27000): reactor threads, admission control, downstream sockets, auth and control endpoint.", "params": [
  {"key":"remoted.auth_max_body_size","type":"int","default":5242880,"min":1048576,"max":67108864,"desc":"Hard cap on the authenticated request body size, in bytes (checked by the auth middleware, independent of the transport's own body cap -- https.max_body_size, a regular <remote> setting, not an internal option)."},
  {"key":"remoted.auth_max_decoded_body_size","type":"int","default":33554432,"min":1048576,"max":1073741824,"desc":"Hard cap on an authenticated request body after Content-Encoding: zstd decompression, in bytes."},
  {"key":"remoted.authd_connect_timeout","type":"int","default":2,"min":1,"max":60,"desc":"Seconds remoted waits to connect to authd's local enrollment socket."},
  {"key":"remoted.authd_max_queue_size","type":"int","default":256,"min":1,"max":65536,"desc":"Enrollment requests that may wait for an authd worker before further ones are refused."},
  {"key":"remoted.authd_response_timeout","type":"int","default":0,"min":0,"max":120,"desc":"Seconds remoted waits for authd's answer once connected."},
  {"key":"remoted.authd_worker_threads","type":"int","default":8,"min":1,"max":32,"desc":"Concurrent connections remoted keeps to authd for enrollment."},
  {"key":"remoted.control_groups_refresh_interval","type":"int","default":60,"min":1,"max":3600,"desc":"Seconds between refreshes of the cached shared-group listing used to answer /control."},
  {"key":"remoted.control_keepalive_throttle","type":"int","default":60,"min":1,"max":3600,"desc":"Minimum seconds between two wazuh-db keepalive writes for the same agent."},
  {"key":"remoted.control_msg_queue_size","type":"int","default":16384,"min":4096,"max":1048576,"desc":"Queue size for agent keep-alive and control messages."},
  {"key":"remoted.control_tm_concurrency","type":"int","default":4,"min":1,"max":64,"desc":"Concurrent task-manager requests the control plane may have in flight."},
  {"key":"remoted.control_tm_deadline","type":"int","default":2000,"min":100,"max":30000,"desc":"Milliseconds a single task-manager round-trip may take."},
  {"key":"remoted.control_tm_max_queue_size","type":"int","default":10000,"min":100,"max":1000000,"desc":"High-water mark for queued task-manager requests."},
  {"key":"remoted.control_wdb_max_queue_size","type":"int","default":10000,"min":100,"max":1000000,"desc":"High-water mark for queued wazuh-db requests; over it the handler reports QueueFull."},
  {"key":"remoted.control_wdb_request_connections","type":"int","default":4,"min":1,"max":64,"desc":"Size of the wazuh-db connection pool the control plane uses."},
  {"key":"remoted.control_wdb_roundtrip_deadline","type":"int","default":5000,"min":100,"max":30000,"desc":"Milliseconds a wazuh-db request may take, from when it is queued until its answer, before the control handler gives up."},
  {"key":"remoted.downstream_connect_timeout","type":"int","default":2,"min":1,"max":60,"desc":"Seconds to wait for the connect to a downstream service's Unix socket (the engine's event ingress for /stateless, the inventory sync server for /stateful, /stats and /config) to complete."},
  {"key":"remoted.downstream_io_threads","type":"int","default":0,"min":0,"max":256,"desc":"Number of threads running the downstream UDS client's io_context."},
  {"key":"remoted.downstream_max_response_body_size","type":"int","default":10485760,"min":1048576,"max":67108864,"desc":"Cap on a downstream response body, in bytes."},
  {"key":"remoted.downstream_post_process_threads","type":"int","default":0,"min":0,"max":256,"desc":"Number of threads running the per-endpoint post-processors (build/deliver the reply once the downstream service answers)."},
  {"key":"remoted.downstream_response_timeout","type":"int","default":5,"min":1,"max":300,"desc":"Seconds to wait for the downstream service's response after the write completes."},
  {"key":"remoted.downstream_stateful_response_timeout","type":"int","default":20,"min":1,"max":3600,"desc":"Seconds to wait for the inventory sync server's answer to a relayed POST /stateful request."},
  {"key":"remoted.downstream_stateful_retry_after","type":"int","default":20,"min":0,"max":3600,"desc":"Retry-After, in seconds, of the 503 answered when remoted.downstream_stateful_response_timeout elapses on a relayed POST /stateful."},
  {"key":"remoted.downstream_write_timeout","type":"int","default":5,"min":1,"max":300,"desc":"Seconds to wait for the request body write to the downstream service to complete."},
  {"key":"remoted.enroll_password_refresh_interval","type":"int","default":10,"min":1,"max":3600,"desc":"Seconds between fallback polls of the two authd-written secret files POST /enroll authenticates against: /etc/wazuh-manager/authd.pass (the shared enrollment password, Password mode) and /etc/wazuh-manager/enrollment_tokens.json (the enrollment token store, every mode)."},
  {"key":"remoted.http_buffer_size","type":"int","default":8192,"min":1,"max":1048576,"desc":"Socket read buffer size for the HTTPS agent server, in bytes."},
  {"key":"remoted.http_concurrent_accepts","type":"int","default":0,"min":0,"max":64,"desc":"Maximum concurrent in-progress TCP accepts for the HTTPS agent server."},
  {"key":"remoted.http_content_encoding_enabled","type":"int","default":1,"min":0,"max":1,"desc":"Whether the HTTPS listener accepts request bodies compressed with Content-Encoding: zstd."},
  {"key":"remoted.http_io_threads","type":"int","default":0,"min":0,"max":64,"desc":"Number of I/O threads (accept + read/write) for the HTTPS agent server."},
  {"key":"remoted.http_max_header_count","type":"int","default":64,"min":1,"max":1024,"desc":"Maximum number of HTTP headers accepted per request."},
  {"key":"remoted.http_max_header_name_size","type":"int","default":256,"min":1,"max":8192,"desc":"Maximum accepted HTTP header name size, in bytes."},
  {"key":"remoted.http_max_header_value_size","type":"int","default":8192,"min":1,"max":65536,"desc":"Maximum accepted HTTP header value size, in bytes."},
  {"key":"remoted.http_max_pipelined_requests","type":"int","default":4,"min":1,"max":64,"desc":"Maximum in-flight unanswered requests per connection (HTTP pipelining depth)."},
  {"key":"remoted.http_max_url_size","type":"int","default":2048,"min":1,"max":65536,"desc":"Maximum accepted URL size, in bytes."},
  {"key":"remoted.http_read_timeout","type":"int","default":10,"min":1,"max":300,"desc":"Seconds to wait for a full request to arrive on a connection."},
  {"key":"remoted.http_request_timeout","type":"int","default":30,"min":1,"max":600,"desc":"Seconds a request may take to be handled end-to-end."},
  {"key":"remoted.http_stream_chunk_size","type":"int","default":65536,"min":4096,"max":1048576,"desc":"Bytes per chunk when streaming a response body (POST /download)."},
  {"key":"remoted.http_worker_threads","type":"int","default":0,"min":0,"max":256,"desc":"Number of worker threads that run endpoint handlers (auth + business logic), off the I/O threads."},
  {"key":"remoted.http_write_timeout","type":"int","default":10,"min":1,"max":300,"desc":"Seconds to wait for a response write to complete."},
  {"key":"remoted.jwt_clock_skew","type":"int","default":30,"min":0,"max":43200,"desc":"Tolerated clock difference (seconds) between an agent and the manager, applied in both directions: a token may be issued up to jwt_clock_skew seconds in the future, and is still accepted up to jwt_clock_skew seconds after its exp."},
  {"key":"remoted.jwt_max_age","type":"int","default":60,"min":1,"max":43200,"desc":"Maximum age (seconds) of an agent's bearer token (wazuh-agent+jwt) the auth middleware accepts: a token is usable while now - iat <= jwt_max_age + jwt_clock_skew."},
  {"key":"remoted.max_attempts","type":"int","default":4,"min":1,"max":16,"desc":"Maximum sends of a request to a UDP legacy agent (and maximum waits for its answer) before the request fails with err Maximum attempts exceeded."},
  {"key":"remoted.max_deferred_requests","type":"int","default":128,"min":1,"max":65536,"desc":"Maximum requests parked awaiting a downstream service before replying with HTTP 503."},
  {"key":"remoted.max_handshakes_per_source","type":"int","default":32,"min":0,"max":65536,"desc":"Maximum connections from one address that may be in the TLS handshake at once."},
  {"key":"remoted.max_inflight_bytes","type":"int","default":268435456,"min":1048576,"max":1073741824,"desc":"Maximum in-flight (unprocessed) request payload bytes before the HTTPS server sheds load with HTTP 503."},
  {"key":"remoted.max_inflight_bytes_per_agent","type":"int","default":0,"min":0,"max":1073741824,"desc":"Maximum bytes of decoded request bodies a single agent may hold at once, across all its open requests on the authenticated routes."},
  {"key":"remoted.max_parallel_connections","type":"int","default":256,"min":1,"max":65536,"desc":"Maximum simultaneous HTTPS connections."},
  {"key":"remoted.max_requests_per_agent","type":"int","default":6,"min":1,"max":65536,"desc":"Maximum requests a single agent may have open at once on the authenticated routes."},
  {"key":"remoted.vd_scan_read_timeout","type":"int","default":5,"min":1,"max":300,"desc":"Seconds to wait for VD's answer to the inline POST /scan/vd admission relay."},
  {"key":"remoted.vd_scan_write_timeout","type":"int","default":5,"min":1,"max":300,"desc":"Seconds to wait for the write side of the same inline POST /scan/vd relay to VD."}
 ]},
 "remoted": {"label": "Remoted, core and legacy listener", "desc": "Queues, worker pools and the legacy (4.x) listener on 1514.", "params": [
  {"key":"remoted.batch_events_capacity","type":"int","default":131072,"min":0,"max":1048576,"desc":"Item capacity of the legacy events queue that the dispatcher batches, enriches and posts to the engine."},
  {"key":"remoted.batch_events_max_bytes","type":"int","default":33554432,"min":1024,"max":2147483647,"desc":"Maximum bytes held in the events queue (events forwarded to the engine).","note":"docs narrow the minimum to 1024"},
  {"key":"remoted.batch_events_per_agent_capacity","type":"int","default":131072,"min":0,"max":1048576,"desc":"Maximum events one agent may hold in the legacy events queue; further events from that agent are discarded until its share drains."},
  {"key":"remoted.buffer_relax","type":"int","default":1,"min":0,"max":2,"desc":"What a legacy TCP connection's receive buffer does with its memory after the complete messages in it have been dispatched."},
  {"key":"remoted.comp_average_printout","type":"int","default":19999,"min":10,"max":999999,"desc":"Messages remoted compresses and encrypts for legacy agents between two debug lines (Event count after '<n>': <original>-><compressed> (<rate>%)) reporting the average compression rate."},
  {"key":"remoted.debug","type":"int","default":0,"min":0,"max":2,"desc":"Debug logging level for remoted module."},
  {"key":"remoted.disk_storage","type":"int","default":0,"min":0,"max":1,"desc":"Where remoted builds a group's merged.mg before comparing it with the current one."},
  {"key":"remoted.enrich_cache_expire_time","type":"int","default":300,"min":60,"max":86400,"desc":"Agent metadata cache expiration time in seconds."},
  {"key":"remoted.keyupdate_interval","type":"int","default":10,"min":1,"max":3600,"desc":"Interval in seconds for reloading agent key files."},
  {"key":"remoted.legacy_task_polling_interval","type":"int","default":900,"min":300,"max":86400,"desc":"Interval in seconds between polls of the Task Manager's pending tasks on behalf of connected agents older than v5.0.0."},
  {"key":"remoted.merge_shared","type":"int","default":1,"min":0,"max":1,"desc":"Build each group's merged.mg from the files in its shared/ directory."},
  {"key":"remoted.pass_empty_keyfile","type":"int","default":1,"min":0,"max":1,"desc":"Allow remoted to start when client.keys is missing, unreadable or empty."},
  {"key":"remoted.queue_max_bytes","type":"int","default":67108864,"min":1024,"max":2147483647,"desc":"Maximum bytes held in the input message queue (messages received from agents).","note":"docs narrow the minimum to 1024"},
  {"key":"remoted.receive_chunk","type":"int","default":4096,"min":1024,"max":16384,"desc":"Bytes read per recv() call from a legacy TCP connection (the per-connection receive buffer grows in steps of this size)."},
  {"key":"remoted.recv_counter_flush","type":"int","default":128,"min":10,"max":999999,"desc":"Messages remoted accepts from legacy agents between two writes of a message counter to an agent's RIDS file (queue/rids/<id>)."},
  {"key":"remoted.recv_timeout","type":"int","default":1,"min":1,"max":60,"desc":"Receive timeout (SO_RCVTIMEO), in seconds, set on the legacy TCP listening socket."},
  {"key":"remoted.request_pool","type":"int","default":1024,"min":1,"max":4096,"desc":"Maximum requests to legacy agents in progress at once."},
  {"key":"remoted.request_rto_msec","type":"int","default":0,"min":0,"max":999,"desc":"Retransmission timeout (milliseconds part), added to remoted.request_rto_sec."},
  {"key":"remoted.request_rto_sec","type":"int","default":1,"min":0,"max":60,"desc":"Retransmission timeout (seconds part) for a request to a UDP legacy agent: how long remoted waits for its ACK before resending."},
  {"key":"remoted.request_timeout","type":"int","default":10,"min":1,"max":600,"desc":"Seconds a request waits for a free slot in remoted.request_pool before it is refused with Request pool is full."},
  {"key":"remoted.response_timeout","type":"int","default":60,"min":1,"max":3600,"desc":"Seconds remoted waits for a legacy agent's answer to a request once it has been delivered (Response timeout for request counter ..."},
  {"key":"remoted.rlimit_nofile","type":"int","default":65536,"min":1024,"max":1048576,"desc":"Soft file descriptor limit remoted raises itself to at start."},
  {"key":"remoted.send_buffer_size","type":"int","default":131072,"min":65536,"max":1048576,"desc":"Capacity, in bytes, of the per-connection send buffer holding messages queued for a legacy TCP agent."},
  {"key":"remoted.send_chunk","type":"int","default":4096,"min":512,"max":16384,"desc":"Maximum bytes taken from a legacy agent's send buffer per socket write."},
  {"key":"remoted.send_timeout_to_retry","type":"int","default":1,"min":1,"max":60,"desc":"Seconds remoted waits before retrying once to queue a message for a legacy agent whose per-connection send buffer (remoted.send_buffer_size) is full."},
  {"key":"remoted.sender_pool","type":"int","default":8,"min":1,"max":64,"desc":"Number of threads that push a group's merged.mg to legacy (4.x) agents."},
  {"key":"remoted.shared_reload","type":"int","default":10,"min":1,"max":18000,"desc":"Interval in seconds for reloading shared configuration files."},
  {"key":"remoted.tcp_keepcnt","type":"int","default":3,"min":1,"max":50,"desc":"Number of unacknowledged TCP keepalive probes before considering connection dead."},
  {"key":"remoted.tcp_keepidle","type":"int","default":30,"min":1,"max":7200,"desc":"Idle seconds before TCP keepalive probes are sent on the legacy TCP listener's sockets."},
  {"key":"remoted.tcp_keepintvl","type":"int","default":10,"min":1,"max":100,"desc":"Interval in seconds between TCP keepalive probes."},
  {"key":"remoted.unauthenticated_max","type":"int","default":16384,"min":64,"max":1048576,"desc":"Maximum number of legacy TCP connections open at once without having authenticated (see remoted.unauthenticated_timeout)."},
  {"key":"remoted.unauthenticated_timeout","type":"int","default":60,"min":10,"max":3600,"desc":"Seconds a legacy TCP connection may stay open without authenticating, that is, without sending a message that decrypts with a registered agent's key."},
  {"key":"remoted.verify_msg_id","type":"int","default":0,"min":0,"max":1,"desc":"Reject agent messages whose counter is not higher than the last one received from that agent, to detect replayed messages."},
  {"key":"remoted.worker_pool","type":"int","default":4,"min":1,"max":16,"desc":"Number of message-handler threads that decrypt and dispatch messages read off the legacy listener."}
 ]},
 "limits": {"label": "Agent inventory limits", "desc": "Caps remoted hands every 5.x agent at startup. Set the same values on every cluster node.", "params": [
  {"key":"fim.file_limit","type":"int","default":30000,"min":0,"max":2147483647,"desc":"Inventory cap the manager sends to 5.x agents in the startup answer (limits object)."},
  {"key":"fim.registry_key_limit","type":"int","default":30000,"min":0,"max":2147483647,"desc":"Inventory cap the manager sends to 5.x agents in the startup answer (limits object)."},
  {"key":"fim.registry_value_limit","type":"int","default":30000,"min":0,"max":2147483647,"desc":"Inventory cap the manager sends to 5.x agents in the startup answer (limits object)."},
  {"key":"sca.checks_limit","type":"int","default":30000,"min":0,"max":2147483647,"desc":"Inventory cap the manager sends to 5.x agents in the startup answer (limits object)."},
  {"key":"syscollector.browser_extensions_limit","type":"int","default":30000,"min":0,"max":2147483647,"desc":"Inventory cap the manager sends to 5.x agents in the startup answer (limits object)."},
  {"key":"syscollector.groups_limit","type":"int","default":30000,"min":0,"max":2147483647,"desc":"Inventory cap the manager sends to 5.x agents in the startup answer (limits object)."},
  {"key":"syscollector.hardware_limit","type":"int","default":30000,"min":0,"max":2147483647,"desc":"Inventory cap the manager sends to 5.x agents in the startup answer (limits object)."},
  {"key":"syscollector.hotfixes_limit","type":"int","default":30000,"min":0,"max":2147483647,"desc":"Inventory cap the manager sends to 5.x agents in the startup answer (limits object)."},
  {"key":"syscollector.network_address_limit","type":"int","default":30000,"min":0,"max":2147483647,"desc":"Inventory cap the manager sends to 5.x agents in the startup answer (limits object)."},
  {"key":"syscollector.network_iface_limit","type":"int","default":30000,"min":0,"max":2147483647,"desc":"Inventory cap the manager sends to 5.x agents in the startup answer (limits object)."},
  {"key":"syscollector.network_protocol_limit","type":"int","default":30000,"min":0,"max":2147483647,"desc":"Inventory cap the manager sends to 5.x agents in the startup answer (limits object)."},
  {"key":"syscollector.os_info_limit","type":"int","default":30000,"min":0,"max":2147483647,"desc":"Inventory cap the manager sends to 5.x agents in the startup answer (limits object)."},
  {"key":"syscollector.packages_limit","type":"int","default":30000,"min":0,"max":2147483647,"desc":"Inventory cap the manager sends to 5.x agents in the startup answer (limits object)."},
  {"key":"syscollector.ports_limit","type":"int","default":30000,"min":0,"max":2147483647,"desc":"Inventory cap the manager sends to 5.x agents in the startup answer (limits object)."},
  {"key":"syscollector.processes_limit","type":"int","default":30000,"min":0,"max":2147483647,"desc":"Inventory cap the manager sends to 5.x agents in the startup answer (limits object)."},
  {"key":"syscollector.services_limit","type":"int","default":30000,"min":0,"max":2147483647,"desc":"Inventory cap the manager sends to 5.x agents in the startup answer (limits object)."},
  {"key":"syscollector.users_limit","type":"int","default":30000,"min":0,"max":2147483647,"desc":"Inventory cap the manager sends to 5.x agents in the startup answer (limits object)."}
 ]},
 "wazuh_db": {"label": "Wazuh DB (wazuh-manager-db)", "desc": "Worker pool, commit timing, open databases, vacuum policy.", "params": [
  {"key":"wazuh_db.check_fragmentation_interval","type":"int","default":7200,"min":1,"max":30758400,"desc":"Seconds between fragmentation checks"},
  {"key":"wazuh_db.commit_time_max","type":"int","default":60,"min":1,"max":3600,"desc":"Commit an open transaction once it is this many seconds old"},
  {"key":"wazuh_db.commit_time_min","type":"int","default":10,"min":1,"max":3600,"desc":"Commit an open transaction once this many seconds pass without a query"},
  {"key":"wazuh_db.debug","type":"int","default":0,"min":0,"max":2,"desc":"Debug level"},
  {"key":"wazuh_db.fragmentation_delta","type":"int","default":5,"min":0,"max":100,"desc":"Growth in fragmentation since the last vacuum needed to vacuum again"},
  {"key":"wazuh_db.fragmentation_threshold","type":"int","default":75,"min":0,"max":100,"desc":"Fragmentation percentage above which a vacuum is considered"},
  {"key":"wazuh_db.free_pages_percentage","type":"int","default":0,"min":0,"max":99,"desc":"Minimum free-pages percentage required before any vacuum"},
  {"key":"wazuh_db.max_fragmentation","type":"int","default":90,"min":0,"max":100,"desc":"Fragmentation percentage that forces a vacuum"},
  {"key":"wazuh_db.open_db_limit","type":"int","default":64,"min":1,"max":4096,"desc":"Databases kept open before idle ones are closed; global.db is never closed"},
  {"key":"wazuh_db.rlimit_nofile","type":"int","default":65536,"min":1024,"max":1048576,"desc":"Soft file descriptor limit, capped by the hard limit the daemon inherits"},
  {"key":"wazuh_db.worker_pool_size","type":"int","default":8,"min":1,"max":32,"desc":"Worker thread pool size"}
 ]},
 "authd": {"label": "Enrollment (wazuh-manager-authd)", "desc": "Agent limit, deletion purge delay and local-socket timeouts.", "params": [
  {"key":"auth.timeout_microseconds","type":"int","default":0,"min":0,"max":999999,"desc":"Receive timeout of a local-socket client connection, microseconds part (both parts 0 = no timeout)."},
  {"key":"auth.timeout_seconds","type":"int","default":1,"min":0,"max":2147483647,"desc":"Receive timeout of a local-socket client connection, seconds part (both parts 0 = no timeout)."},
  {"key":"authd.debug","type":"int","default":0,"min":0,"max":2,"desc":"The daemon's debug level when it is started without -d: 1 is debug, 2 is verbose debug."},
  {"key":"authd.max_agents","type":"int","default":0,"min":0,"max":2147483647,"desc":"The largest number of agents the keystore may hold."},
  {"key":"authd.purge_delay","type":"int","default":120,"min":0,"max":3600,"desc":"How long an agent's deletion waits before its indexer purge may run."},
  {"key":"authd.wdb_timeout","type":"int","default":10,"min":1,"max":300,"desc":"How long authd allows for one wazuh-db round trip."}
 ]},
 "tasks": {"label": "Task Manager", "desc": "Durable task queue: retries, timeouts, retention, log rotation, agent monitoring.", "params": [
  {"key":"wazuh_modules.manager_task_backoff_base","type":"int","default":30,"min":1,"max":3600,"desc":"First retry delay; doubles from here","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.manager_task_backoff_cap","type":"int","default":900,"min":1,"max":86400,"desc":"Ceiling for both ladders","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.manager_task_claim_grace","type":"int","default":30,"min":1,"max":3600,"desc":"Slack before a claimed row is considered reclaimable","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.manager_task_create_timeout","type":"int","default":2,"min":1,"max":60,"desc":"Deadline on the vulnerability scanner's own call to create a row; read by the scanner's configuration reader, not by this module; an out-of-range value fails wazuh-manager-modulesd -t all the same"},
  {"key":"wazuh_modules.manager_task_dead_letter_retention_days","type":"int","default":30,"min":1,"max":3650,"desc":"dead_letter rows older than N days","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.manager_task_defer_base","type":"int","default":5,"min":1,"max":3600,"desc":"First deferral delay","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.manager_task_delete_old_agents","type":"int","default":0,"min":0,"max":9600,"desc":"retention window in minutes, on top of agents_disconnection_time"},
  {"key":"wazuh_modules.manager_task_delete_old_batch","type":"int","default":200,"min":1,"max":100000,"desc":"agents the retention sweep examines per attempt","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.manager_task_delete_old_budget","type":"int","default":30,"min":1,"max":3600,"desc":"seconds a retention-sweep attempt may hold its executor slot","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.manager_task_delete_timeout","type":"int","default":600,"min":1,"max":7200,"desc":"Deadline on one deletion call, and the type's watchdog budget.","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.manager_task_disconnect_log_max","type":"int","default":200,"min":0,"max":1000000,"desc":"agents the disconnection sweep names individually per run; 0 names none","note":"source fallback -1 means module default"},
  {"key":"wazuh_modules.manager_task_executor_threads","type":"int","default":null,"min":1,"max":64,"desc":"Workers that claim and run manager tasks","note":"module computes the default"},
  {"key":"wazuh_modules.manager_task_history_per_schedule","type":"int","default":20,"min":1,"max":100000,"desc":"Keep at most N finished runs per schedule (dead letters are not counted or removed by this rule)","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.manager_task_io_threads","type":"int","default":2,"min":1,"max":64,"desc":"Reactor threads serving the socket.","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.manager_task_log_compress","type":"int","default":1,"min":0,"max":1,"desc":"whether rotated logs are gzipped"},
  {"key":"wazuh_modules.manager_task_log_daily_rotations","type":"int","default":12,"min":1,"max":256,"desc":"rotated slots per day per file","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.manager_task_log_day_wait","type":"int","default":10,"min":1,"max":600,"desc":"offset from local midnight for the daily rotation; 0 is out of range (the slot cannot sit exactly at midnight)","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.manager_task_log_keep_days","type":"int","default":31,"min":0,"max":500,"desc":"how many days rotated logs are kept; 0 keeps none","note":"source fallback -1 means module default"},
  {"key":"wazuh_modules.manager_task_log_rotate","type":"int","default":1,"min":0,"max":1,"desc":"whether either kind of log rotation happens, 0 disables the daily schedule *and* the size-triggered one"},
  {"key":"wazuh_modules.manager_task_log_size_rotate","type":"int","default":512,"min":0,"max":4096,"desc":"threshold for size-based rotation; 0 disables size rotation while leaving the daily one alone","note":"source fallback -1 means module default"},
  {"key":"wazuh_modules.manager_task_max_attempts","type":"int","default":8,"min":1,"max":1000,"desc":"Attempts before dead_letter, for types that have a budget","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.manager_task_max_defer","type":"int","default":48,"min":1,"max":10000,"desc":"Consecutive deferrals before dead_letter","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.manager_task_max_pending_deletes","type":"int","default":20000,"min":0,"max":1000000,"desc":"How many agent deletions may be waiting to reach the indexer before authd refuses new ones with 9021 (1766 through the server API)."},
  {"key":"wazuh_modules.manager_task_max_pending_scans","type":"int","default":64,"min":0,"max":1000000,"desc":"Admission bound on pending on-demand scans.","note":"source fallback -1 means module default"},
  {"key":"wazuh_modules.manager_task_max_rows","type":"int","default":100000,"min":1,"max":100000000,"desc":"Hard ceiling on the table, evicting terminal rows oldest first, completed, then superseded, then failed, dead_letter last","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.manager_task_monitor_agents","type":"int","default":1,"min":0,"max":1,"desc":"whether the disconnection sweep runs at all (the retention sweep is governed by manager_task_delete_old_agents)"},
  {"key":"wazuh_modules.manager_task_poll_interval","type":"int","default":60,"min":1,"max":3600,"desc":"Maximum scheduler sleep.","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.manager_task_retention_days","type":"int","default":7,"min":1,"max":3650,"desc":"completed, failed and superseded rows older than N days, measured from when they *reached* that state","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.manager_task_sweep_interval","type":"int","default":60,"min":1,"max":3600,"desc":"How often ownership is swept and stalls are reported","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.manager_task_vd_scan_timeout","type":"int","default":300,"min":1,"max":3600,"desc":"Deadline on one scan call, and the type's watchdog budget","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.manager_task_wdb_timeout","type":"int","default":10,"min":1,"max":600,"desc":"Deadline on each agent-removal request the retention sweep sends to wazuh-manager-authd.","note":"source fallback 0 means module default"}
 ]},
 "upgrade": {"label": "Agent upgrades", "desc": "Upgrade batches, WPK downloads and version cache.", "params": [
  {"key":"wazuh_modules.upgrade_batch_deadline","type":"int","default":180,"min":10,"max":3600,"desc":"seconds one batch may take before its remaining agents are failed","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.upgrade_download_attempts","type":"int","default":3,"min":1,"max":10,"desc":"tries per WPK before giving up","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.upgrade_download_timeout","type":"int","default":45000,"min":1000,"max":600000,"desc":"milliseconds per download attempt","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.upgrade_max_agents","type":"int","default":500,"min":1,"max":100000,"desc":"largest batch accepted in one request; a larger one answers every agent with error 2","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.upgrade_max_concurrent_downloads","type":"int","default":2,"min":1,"max":32,"desc":"WPK downloads in flight across all batches","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.upgrade_queue_depth","type":"int","default":8,"min":1,"max":1000,"desc":"batches queued before a request is refused","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.upgrade_versions_ttl","type":"int","default":300,"min":0,"max":86400,"desc":"seconds a repository's versions file is cached; 0 fetches every time","note":"source fallback -1 means module default"},
  {"key":"wazuh_modules.upgrade_workers","type":"int","default":null,"min":1,"max":16,"desc":"upgrade batches run at once","note":"module computes the default"}
 ]},
 "inventory": {"label": "Inventory sync server", "desc": "Transport, admission and indexer connectors of the inventory sync endpoint in modulesd.", "params": [
  {"key":"wazuh_modules.inventory_sync_server_body_timeout","type":"int","default":30,"min":0,"max":3600,"desc":"Seconds from the head to a complete body.","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.inventory_sync_server_buffer_size","type":"int","default":8192,"min":0,"max":1048576,"desc":"Per-connection read buffer, in bytes.","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.inventory_sync_server_concurrent_accepts","type":"int","default":2,"min":0,"max":64,"desc":"Accept operations kept in flight.","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.inventory_sync_server_control_max_body_bytes","type":"int","default":65536,"min":0,"max":1048576,"desc":"Declared-length cap of control-class requests; over it 413.","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.inventory_sync_server_control_max_sessions","type":"int","default":256,"min":0,"max":1024,"desc":"Concurrent control-class sessions; over it 503.","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.inventory_sync_server_drain_timeout","type":"int","default":2,"min":0,"max":10,"desc":"Seconds stop() waits for already-dispatched requests to answer before their connections are force-closed.","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.inventory_sync_server_header_timeout","type":"int","default":10,"min":0,"max":3600,"desc":"Seconds from accept to a complete request head.","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.inventory_sync_server_indexer_async_bulk_max_bytes","type":"int","default":4194304,"min":4096,"max":104857600,"desc":"Forwarded as bulk_max_bytes."},
  {"key":"wazuh_modules.inventory_sync_server_indexer_async_flush_interval_seconds","type":"int","default":20,"min":1,"max":3600,"desc":"Forwarded as flush_interval_seconds."},
  {"key":"wazuh_modules.inventory_sync_server_indexer_async_logger_queue_size","type":"int","default":8,"min":1,"max":65536,"desc":"Forwarded as logger_queue_size."},
  {"key":"wazuh_modules.inventory_sync_server_indexer_async_logger_threads","type":"int","default":1,"min":1,"max":64,"desc":"Forwarded as logger_threads."},
  {"key":"wazuh_modules.inventory_sync_server_indexer_async_max_queue_bytes","type":"int","default":67108864,"min":1,"max":2147483647,"desc":"Forwarded as max_queue_bytes.","note":"docs narrow the minimum to 1"},
  {"key":"wazuh_modules.inventory_sync_server_indexer_async_max_retry_delay_seconds","type":"int","default":15,"min":1,"max":3600,"desc":"Forwarded as max_retry_delay_seconds."},
  {"key":"wazuh_modules.inventory_sync_server_indexer_async_request_timeout_seconds","type":"int","default":60,"min":1,"max":3600,"desc":"Forwarded as request_timeout_seconds."},
  {"key":"wazuh_modules.inventory_sync_server_indexer_monitoring_interval_seconds","type":"int","default":10,"min":1,"max":3600,"desc":"Forwarded to the shared indexer session as monitoring_interval_seconds."},
  {"key":"wazuh_modules.inventory_sync_server_indexer_sync_connector_max_bulk_size","type":"int","default":10485760,"min":4096,"max":104857600,"desc":"Forwarded to the Indexer Connector as max_bulk_size: the serialized NDJSON bytes the connector stages before it cuts a _bulk request."},
  {"key":"wazuh_modules.inventory_sync_server_indexer_sync_flush_interval_seconds","type":"int","default":20,"min":1,"max":3600,"desc":"No effect."},
  {"key":"wazuh_modules.inventory_sync_server_indexer_sync_max_bulk_size","type":"int","default":10485760,"min":4096,"max":104857600,"desc":"The ingestion pipeline's group-commit threshold, measured in request payload bytes (wire FlatBuffer size): a worker flushes its open batch once the staged sessions reach this many bytes."},
  {"key":"wazuh_modules.inventory_sync_server_indexer_sync_max_retry_attempts","type":"int","default":5,"min":0,"max":1000,"desc":"Forwarded as max_retry_attempts."},
  {"key":"wazuh_modules.inventory_sync_server_indexer_sync_max_retry_delay_seconds","type":"int","default":15,"min":1,"max":3600,"desc":"Forwarded as max_retry_delay_seconds."},
  {"key":"wazuh_modules.inventory_sync_server_indexer_sync_max_retry_duration_seconds","type":"int","default":15,"min":0,"max":3600,"desc":"Forwarded as max_retry_duration_seconds."},
  {"key":"wazuh_modules.inventory_sync_server_indexer_sync_request_timeout_seconds","type":"int","default":60,"min":1,"max":3600,"desc":"Forwarded as request_timeout_seconds."},
  {"key":"wazuh_modules.inventory_sync_server_io_threads","type":"int","default":0,"min":0,"max":128,"desc":"Reactor I/O threads of the inventory sync server. 0 sizes the reactor from the host or cgroup."},
  {"key":"wazuh_modules.inventory_sync_server_max_body_size","type":"int","default":0,"min":0,"max":536870912,"desc":"Request body cap in bytes; over it the request is answered 413."},
  {"key":"wazuh_modules.inventory_sync_server_max_header_name_size","type":"int","default":256,"min":0,"max":65536,"desc":"Max header name size in bytes; over it 431.","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.inventory_sync_server_max_header_value_size","type":"int","default":8192,"min":0,"max":1048576,"desc":"Max header value size in bytes; over it 431.","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.inventory_sync_server_max_inflight_bytes","type":"int","default":268435456,"min":1,"max":2147483647,"desc":"Total in-flight request payload bytes; over it 503.","note":"source fallback -1 means module default; docs narrow the minimum to 1"},
  {"key":"wazuh_modules.inventory_sync_server_max_parallel_connections","type":"int","default":1024,"min":0,"max":65536,"desc":"Max simultaneous connections; over it 503 and close.","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.inventory_sync_server_max_sessions_per_agent","type":"int","default":2,"min":1,"max":1024,"desc":"Sessions one agent may have admitted and not yet answered, across the sync pipeline and the vulnerability-detection scan lane."},
  {"key":"wazuh_modules.inventory_sync_server_max_url_size","type":"int","default":2048,"min":0,"max":65536,"desc":"Max request-target size in bytes; over it 414.","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.inventory_sync_server_reserved_control_connections","type":"int","default":64,"min":0,"max":256,"desc":"Accept headroom the data plane can never consume.","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.inventory_sync_server_response_timeout","type":"int","default":300,"min":0,"max":3600,"desc":"Seconds from handler dispatch to a delivered response.","note":"source fallback 0 means module default"},
  {"key":"wazuh_modules.inventory_sync_server_session_query_batch_size","type":"int","default":null,"min":100,"max":10000,"desc":"Indexer search page size of the checksum verification (ModuleCheck sessions), which pages the agent's documents with search_after.","note":"module computes the default; docs narrow the minimum to 100"},
  {"key":"wazuh_modules.inventory_sync_server_sync_queue_bytes","type":"int","default":67108864,"min":1048576,"max":1073741824,"desc":"Admission cap, in bytes, for sessions accepted by the transport but not yet applied by a worker."},
  {"key":"wazuh_modules.inventory_sync_server_sync_workers","type":"int","default":0,"min":0,"max":64,"desc":"Sharded ingestion workers applying accepted sessions."},
  {"key":"wazuh_modules.inventory_sync_server_vd_feed_retry_after_seconds","type":"int","default":10,"min":10,"max":1800,"desc":"Retry-After value, in seconds, answered with 503 while the vulnerability feed is not ready (or the scanner is enabled here but still starting up)."},
  {"key":"wazuh_modules.inventory_sync_server_vd_scan_queue_slots","type":"int","default":0,"min":0,"max":256,"desc":"Sessions and on-demand scan requests allowed to wait for a VD worker."},
  {"key":"wazuh_modules.inventory_sync_server_vd_workers","type":"int","default":0,"min":0,"max":64,"desc":"Workers on the vulnerability-detection scan lane."},
  {"key":"wazuh_modules.inventory_sync_server_write_timeout","type":"int","default":10,"min":0,"max":3600,"desc":"Seconds allowed to write one response.","note":"source fallback 0 means module default"}
 ]},
 "vulnerability": {"label": "Vulnerability detection", "desc": "Scan workers, CPE cache and the scanner's indexer bulk settings.", "params": [
  {"key":"vulnerability-detection.scan_workers","type":"int","default":0,"min":0,"max":64,"desc":"Concurrent scan slots. 0 = half the host's cores, minimum 1."},
  {"key":"vulnerability-detection.translation_lru_size","type":"int","default":2048,"min":1,"max":100000,"desc":"LRU cache size for OS/package -> CPE translation lookups"},
  {"key":"wazuh_modules.indexer_bulk_size_bytes","type":"int","default":10485760,"min":4096,"max":104857600,"desc":"Indexer bulk size threshold in bytes (4 KB to 100 MB)"},
  {"key":"wazuh_modules.indexer_flush_interval","type":"int","default":20,"min":1,"max":3600,"desc":"Indexer periodic flush interval in seconds"},
  {"key":"wazuh_modules.indexer_max_retry_attempts","type":"int","default":5,"min":0,"max":1000,"desc":"Failed attempts allowed per indexer operation before it is abandoned"},
  {"key":"wazuh_modules.indexer_max_retry_duration_seconds","type":"int","default":15,"min":0,"max":3600,"desc":"Wall-clock retry budget per indexer operation, in seconds"}
 ]},
 "modules": {"label": "Modules daemon and shared", "desc": "wazuh-manager-modulesd common options, agent database sync, thread stack size.", "params": [
  {"key":"wazuh_database.interval","type":"int","default":60,"min":0,"max":86400,"desc":"Seconds between two polls in interval mode."},
  {"key":"wazuh_database.max_queued_events","type":"int","default":0,"min":0,"max":2147483647,"desc":"Capacity of the module's internal queue of pending paths in real-time mode."},
  {"key":"wazuh_database.real_time","type":"int","default":1,"min":0,"max":1,"desc":"How changes to client.keys and /etc/wazuh-manager/shared/ are noticed."},
  {"key":"wazuh_database.sync_agents","type":"int","default":1,"min":0,"max":1,"desc":"Whether the module runs at all."},
  {"key":"wazuh_modules.debug","type":"int","default":0,"min":0,"max":2,"desc":"Debug level of wazuh-manager-modulesd (the -d flag overrides it)"},
  {"key":"wazuh_modules.kill_timeout","type":"int","default":10,"min":0,"max":3600,"desc":"Seconds a module's child process gets to exit at shutdown before it is killed; no manager module starts one"},
  {"key":"wazuh_modules.max_eps","type":"int","default":100,"min":1,"max":1000,"desc":"Events per second of the agent-side modules; read and range-checked, but no manager module paces on it"},
  {"key":"wazuh_modules.rlimit_nofile","type":"int","default":65536,"min":8192,"max":1048576,"desc":"Soft file descriptor limit of wazuh-manager-modulesd, see File descriptor limits"},
  {"key":"wazuh_modules.socket_timeout","type":"int","default":1,"min":1,"max":60,"desc":"Longest time, in seconds, a local client of the wazuh-manager-modulesd request socket can go without sending the next part of its request, or without reading the reply, before the connection is dropped."},
  {"key":"wazuh_modules.task_nice","type":"int","default":10,"min":-20,"max":19,"desc":"Nice value of the external programs a module launches; no manager module launches one"},
  {"key":"wazuh_modules.unmask_credentials","type":"int","default":0,"min":0,"max":1,"desc":"Reports module credentials in clear instead of as *; read and range-checked, but the modules that hold credentials run only on agents"},
  {"key":"wazuh.thread_stack_size","type":"int","default":8192,"min":2048,"max":65536,"desc":"Stack size, in KiB, of the threads wazuh-manager-remoted and wazuh-manager-modulesd start; read at each thread creation, so no daemon's -t reads it and wazuh-manager-control check passes an out-of-range value that then stops the daemon at start"}
 ]}
}""")
OTHER_KEYS = json.loads(r"""{"agent.enrollment_retry_delta":"read by agents, not by the manager","agent.enrollment_retry_max":"read by agents, not by the manager","agent.https_backoff_base":"read by agents, not by the manager","agent.https_backoff_cap":"read by agents, not by the manager","agent.https_compression_enabled":"read by agents, not by the manager","agent.https_control_attempts":"read by agents, not by the manager","agent.https_download_attempts":"read by agents, not by the manager","agent.https_producer_pause_threshold":"read by agents, not by the manager","agent.https_rejected_retry_interval":"read by agents, not by the manager","agent.https_request_timeout":"read by agents, not by the manager","agent.https_stateful_attempts":"read by agents, not by the manager","agent.https_stateful_timeout":"read by agents, not by the manager","agent.https_stateless_attempts":"read by agents, not by the manager","agent.https_wpk_max_download_bytes":"read by agents, not by the manager","agent.remote_conf":"read by agents, not by the manager","agent.sync_max_blocks_per_cycle":"read by agents, not by the manager","agent_info.max_entries":"read by agents, not by the manager","agent_info.ttl":"read by agents, not by the manager","analysisd.cm_ruleset_path":"engine setting the tuner does not offer (path, socket, URL, list or switch)","analysisd.drop_privileges":"engine setting the tuner does not offer (path, socket, URL, list or switch)","analysisd.geo_db_path":"engine setting the tuner does not offer (path, socket, URL, list or switch)","analysisd.geo_manifest_url":"engine setting the tuner does not offer (path, socket, URL, list or switch)","analysisd.indexer_ssl_certificate":"engine setting the tuner does not offer (path, socket, URL, list or switch)","analysisd.indexer_ssl_key":"engine setting the tuner does not offer (path, socket, URL, list or switch)","analysisd.kvdb_ioc_input_path":"engine setting the tuner does not offer (path, socket, URL, list or switch)","analysisd.kvdb_ioc_path":"engine setting the tuner does not offer (path, socket, URL, list or switch)","analysisd.logging_level":"engine setting the tuner does not offer (path, socket, URL, list or switch)","analysisd.output_path":"engine setting the tuner does not offer (path, socket, URL, list or switch)","analysisd.pid_path":"engine setting the tuner does not offer (path, socket, URL, list or switch)","analysisd.server_api_socket":"engine setting the tuner does not offer (path, socket, URL, list or switch)","analysisd.server_enable_event_processing":"engine setting the tuner does not offer (path, socket, URL, list or switch)","analysisd.server_enriched_events_socket":"engine setting the tuner does not offer (path, socket, URL, list or switch)","analysisd.store_path":"engine setting the tuner does not offer (path, socket, URL, list or switch)","analysisd.streamlog_base_path":"engine setting the tuner does not offer (path, socket, URL, list or switch)","analysisd.streamlog_dumper_pattern":"engine setting the tuner does not offer (path, socket, URL, list or switch)","analysisd.streamlog_events_pattern":"engine setting the tuner does not offer (path, socket, URL, list or switch)","analysisd.tzdb_force_version_update":"engine setting the tuner does not offer (path, socket, URL, list or switch)","analysisd.tzdb_path":"engine setting the tuner does not offer (path, socket, URL, list or switch)","sca.commands_timeout":"read by agents, not by the manager","sca.remote_commands":"read by agents, not by the manager","syscheck.sync_flush_batch_size":"read by agents, not by the manager","syscheck.sync_flush_interval_ms":"read by agents, not by the manager","syscheck.sync_wal_autocheckpoint_pages":"read by agents, not by the manager","wazuh_command.remote_commands":"read by agents, not by the manager"}""")
# END PARAMS

ALL_PARAMS = {x["key"]: x for s in PARAMS.values() for x in s["params"]}


def is_engine(key):
    return key.startswith("analysisd.")


PRESETS = {
    "default": {
        "label": "Default",
        "desc": "Vendor defaults (empty file). Use it to reset.",
        "values": {},
    },
    "many_agents": {
        "label": "Many agents per node",
        "desc": "Thousands of agents on one node: more remoted and wazuh-db workers, a larger control queue, "
                "more open agent databases. Starting point only: change, measure, repeat.",
        "values": {
            "remoted.worker_pool": 8,
            "remoted.sender_pool": 16,
            "remoted.control_msg_queue_size": 65536,
            "wazuh_db.worker_pool_size": 16,
            "wazuh_db.open_db_limit": 1024,
        },
    },
    "burst": {
        "label": "Burst buffers",
        "desc": "Larger engine event queue and remoted queue for drops during restarts or scan bursts. "
                "The byte limits are memory the daemons may hold while the queues fill.",
        "values": {
            "analysisd.event_queue_size": 262144,
            "analysisd.event_queue_max_bytes": 67108864,
            "remoted.queue_max_bytes": 134217728,
        },
    },
    "debug": {
        "label": "Debug (temporary)",
        "desc": "debug=1 on every daemon that has a debug key. Revert after the test.",
        "values": {k: 1 for k in ALL_PARAMS if k.endswith(".debug")},
    },
}


def _int_ok(spec, v):
    if not spec["min"] <= v <= spec["max"]:
        return f"{v} outside [{spec['min']}..{spec['max']}]"
    gap = spec.get("gap")
    if gap and 0 < v < gap:
        return f"{v} not allowed: use 0 or a value from {gap}"
    return None


# Rules that combine keys. Each is (level, keys, test(eff) -> True when broken, message).
# Sources: remoted/src/main.c:162, config/src/wmodules-task-manager.c:177, wazuh_modules/src/wm_inventory_sync_server.c:370,
# remoted/src/secure.c:573 and :721 (these two compare with wazuh-manager.conf values the checker cannot see).
CROSS = [
    ("ERROR", ("remoted.worker_pool", "remoted.verify_msg_id"),
     lambda e: e["remoted.verify_msg_id"] == 1 and e["remoted.worker_pool"] > 1,
     "remoted.verify_msg_id=1 needs remoted.worker_pool=1 (default 4), remoted exits at start"),
    ("ERROR", ("wazuh_modules.manager_task_delete_timeout", "wazuh_modules.manager_task_vd_scan_timeout"),
     lambda e: e["wazuh_modules.manager_task_delete_timeout"] <= e["wazuh_modules.manager_task_vd_scan_timeout"],
     "wazuh_modules.manager_task_delete_timeout must be greater than manager_task_vd_scan_timeout, modulesd exits at start"),
    ("WARN", ("wazuh_modules.inventory_sync_server_indexer_sync_max_retry_attempts",
              "wazuh_modules.inventory_sync_server_indexer_sync_max_retry_duration_seconds"),
     lambda e: e["wazuh_modules.inventory_sync_server_indexer_sync_max_retry_attempts"] == 0
     and e["wazuh_modules.inventory_sync_server_indexer_sync_max_retry_duration_seconds"] == 0,
     "both inventory sync retry bounds are 0: a persistent indexer failure can pin a flush worker"),
    ("WARN", ("remoted.control_keepalive_throttle",),
     lambda e: e["remoted.control_keepalive_throttle"] >= 450,
     "remoted.control_keepalive_throttle is at or above half of the default <agents_disconnection_time> (900 s): "
     "raise that setting in wazuh-manager.conf above twice the throttle, or healthy agents get marked disconnected"),
    ("WARN", ("remoted.auth_max_body_size",),
     lambda e: e["remoted.auth_max_body_size"] >= 10485760,
     "remoted.auth_max_body_size is 10 MiB or more: if wazuh-manager.conf sets remote.https.max_body_size, keep it "
     "above this value, or agents resend oversized requests that get no answer"),
]


def cross_check(values):
    """values: key -> value for set keys; unset keys take the default."""
    eff = {k: values.get(k, ALL_PARAMS[k]["default"]) for r in CROSS for k in r[1]}
    return [(level, keys, msg) for level, keys, test, msg in CROSS if test(eff)]


def validate(values):
    """Return (clean, errors). None means "not set" (module default) and is dropped."""
    clean, errors = {}, []
    for key, raw in values.items():
        spec = ALL_PARAMS.get(key)
        if spec is None:
            errors.append(f"{key}: unknown parameter")
            continue
        if raw is None:
            continue
        if spec["type"] == "bool":
            if isinstance(raw, bool):
                clean[key] = raw
            elif str(raw).strip().lower() in ("true", "false"):
                clean[key] = str(raw).strip().lower() == "true"
            else:
                errors.append(f"{key}: '{raw}' is not true or false")
            continue
        pattern = r"-?\d+" if spec["min"] < 0 else r"\d+"
        if isinstance(raw, bool) or not re.fullmatch(pattern, str(raw).strip()):
            errors.append(f"{key}: '{raw}' is not an integer in range")
            continue
        v = int(str(raw).strip())
        err = _int_ok(spec, v)
        if err:
            errors.append(f"{key}: {err}")
            continue
        clean[key] = v
    if not errors:
        errors += [msg for level, _, msg in cross_check(clean) if level == "ERROR"]
    return clean, errors


def fmt(v):
    return ("true" if v else "false") if isinstance(v, bool) else str(v)


def generate(values, changed_only=True):
    lines = [f"# {TARGET}",
             f"# Checked against Wazuh {WAZUH_VERSION} ranges. This file is per node and never synchronized.", ""]
    for section in PARAMS.values():
        rows = []
        for spec in section["params"]:
            v = values.get(spec["key"], spec["default"])
            if v is None or (changed_only and v == spec["default"] and type(v) is type(spec["default"])):
                continue
            rows.append(f"{spec['key']}={fmt(v)}")
        if rows:
            lines.append(f"# {section['label']}")
            lines += rows + [""]
    return "\n".join(lines)


# ---------------------------------------------------------------- --check

def _c_lines(text):
    """Yield (lineno, high, low, value) the way shared/src/validate_op.c _read_file() sees each line."""
    for n, line in enumerate(text.splitlines(keepends=True), 1):
        if not line or line[0] in "# \n":
            continue
        dot = line.find(".")
        if dot < 0:
            continue
        high, rest = line[:dot], line[dot + 1:]
        eq = rest.find("=")
        if eq < 0:
            continue
        low, value = rest[:eq].rstrip(" "), rest[eq + 1:].lstrip(" ")
        if "\n" in value:
            value = value[:value.rfind("\n")]
        if "\r" in value:
            value = value[:value.rfind("\r")]
        yield n, high, low, value


def _split_unescaped_hash(s):
    out, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            out.append(s[i:i + 2])
            i += 2
            continue
        if s[i] == "#":
            break
        out.append(s[i])
        i += 1
    return "".join(out)


def _engine_lines(text):
    """Yield (lineno, key, value) the way engine/source/conf/src/fileLoader.cpp parseFile() sees each line."""
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip(" \t\r\n")
        if not line or line[0] == "#":
            continue
        eq, dot = line.find("="), line.find(".")
        if eq < 0 or dot < 0 or dot > eq:
            continue
        high = line[:dot].strip(" \t")
        if high != "analysisd":
            continue
        low = line[dot + 1:eq].strip(" \t")
        value = _split_unescaped_hash(line[eq + 1:]).strip(" \t\r\n")
        value = re.sub(r"\\([#\\\"'])", r"\1", value)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        yield n, f"{high}.{low}", value


def check_text(text):
    """Return a list of (level, lineno, message). level: ERROR (daemon will not start), WARN, INFO."""
    out = []
    seen_c, eff = {}, {}
    for n, high, low, value in _c_lines(text):
        key = f"{high}.{low}"
        if is_engine(key) or high[:1] == "\t":  # tab-led lines never match a section, reported below
            continue
        spec = ALL_PARAMS.get(key)
        if key in seen_c:
            out.append(("WARN", n, f"{key}: duplicate, C daemons use line {seen_c[key]} (first line wins)"))
            continue
        seen_c[key] = n
        if spec is None:
            if key in OTHER_KEYS:
                out.append(("INFO", n, f"{key}: {OTHER_KEYS[key]}, not checked"))
            else:
                out.append(("WARN", n, f"{key}: no manager daemon reads this key (typo?)"))
            continue
        if value == "":
            out.append(("ERROR", n, f"{key}: empty value stops the daemon"))
            continue
        if not re.fullmatch(r"-?\d+", value) or not INT_MIN <= int(value) <= INT_MAX:
            hint = " (inline comment or trailing space?)" if re.match(r"-?\d+[ \t#]", value) else ""
            out.append(("ERROR", n, f"{key}: '{value}' is not a plain integer{hint}, the daemon exits (2302)"))
            continue
        err = _int_ok(spec, int(value))
        if err:
            out.append(("ERROR", n, f"{key}: {err}, the daemon exits at start"))
        else:
            eff[key] = int(value)
    for level, keys, msg in cross_check(eff):
        out.append((level, max((seen_c[k] for k in keys if k in eff), default=0), msg))

    # Lines the C reader skips or cannot parse.
    for n, line in enumerate(text.splitlines(keepends=True), 1):
        body = line.strip(" \t\r\n")
        if len(line.rstrip("\n")) > C_LINE_MAX:
            out.append(("ERROR", n, f"line longer than {C_LINE_MAX} bytes, the C reader splits it"))
        if not body or body[0] == "#":
            continue
        key = body.split("=", 1)[0].strip(" \t")
        if line[0] in " \t" and not is_engine(key):
            out.append(("WARN", n, f"{key}: line starts with whitespace, C daemons ignore it"))
        elif "." not in body or "=" not in body:
            out.append(("WARN", n, "not a key=value line, daemons log an error for it on every read"))

    last_engine = {}
    for n, key, value in _engine_lines(text):
        if key in last_engine:
            out.append(("WARN", last_engine[key][0], f"{key}: overridden by line {n} (engine: last line wins)"))
        last_engine[key] = (n, value)
    for key, (n, value) in last_engine.items():
        spec = ALL_PARAMS.get(key)
        if spec is None:
            if key in OTHER_KEYS:
                out.append(("INFO", n, f"{key}: {OTHER_KEYS[key]}, not checked"))
            else:
                out.append(("WARN", n, f"{key}: the engine ignores unknown keys silently (typo?)"))
            continue
        if spec["type"] == "bool":
            if value.lower() not in ("true", "false"):
                out.append(("ERROR", n, f"{key}: '{value}' is not true or false, the engine exits at start"))
            continue
        cap = spec.get("tuner_cap")
        lo, hi = ENGINE_TYPE_BOUNDS.get(cap, (0, 2**64 - 1))
        if not re.fullmatch(r"-?\d+" if lo < 0 else r"\d+", value) or not lo <= int(value) <= hi:
            out.append(("ERROR", n, f"{key}: '{value}' is not an integer the engine accepts, the engine exits at start"))
            continue
        v = int(value)
        err = _int_ok(spec, v)
        if err and cap:
            out.append(("WARN", n, f"{key}: {err}; the engine checks only the type, the tuner range is advisory"))
            continue
        if err:
            out.append(("ERROR", n, f"{key}: {err}, the engine exits at start"))
    out.sort(key=lambda x: (x[1], x[0]))
    return out


def check_file(path):
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        findings = check_text(fh.read())
    for level, n, msg in findings:
        print(f"{level:5}  line {n}: {msg}")
    errors = sum(1 for f in findings if f[0] == "ERROR")
    print(f"{path}: {errors} error(s), {len(findings) - errors} other finding(s)")
    return 1 if errors else 0


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Wazuh 5 Tuner</title>
<style>
:root {
  --bg:#0d1117;--surface:#161b22;--border:#30363d;
  --text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;
  --warn:#d29922;--danger:#f85149;--ok:#3fb950;--code-bg:#010409;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px;}
.layout{display:grid;grid-template-columns:270px 1fr;min-height:100vh;}
.sidebar{background:var(--surface);border-right:1px solid var(--border);padding:16px;position:sticky;top:0;height:100vh;overflow-y:auto;}
.sidebar h2{font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:12px;}
.nav-item{display:block;padding:8px 10px;border-radius:6px;color:var(--muted);font-size:13px;cursor:pointer;margin-bottom:2px;border:none;background:none;width:100%;text-align:left;}
.nav-item:hover,.nav-item.active{background:rgba(88,166,255,.15);color:var(--accent);}
.nav-count{float:right;font-size:11px;color:var(--accent);}
.preset-btn{display:block;width:100%;text-align:left;padding:8px 10px;border-radius:6px;border:1px solid var(--border);background:var(--bg);color:var(--text);font-size:12px;cursor:pointer;margin-bottom:4px;}
.preset-btn:hover{border-color:var(--accent);color:var(--accent);}
.preset-note{font-size:11px;color:var(--muted);margin-top:6px;line-height:1.4;}
.main{padding:24px 32px;max-width:1100px;}
.section{display:none;}
.section.active{display:block;}
.section-header{margin-bottom:20px;}
.section-header h1{font-size:20px;font-weight:600;margin-bottom:4px;}
.section-header p{color:var(--muted);font-size:13px;line-height:1.5;}
.param-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:12px;}
.param-card.changed{border-color:var(--accent);}
.param-key{font-family:ui-monospace,monospace;font-size:13px;color:var(--accent);margin-bottom:4px;overflow-wrap:anywhere;}
.param-badge{display:inline-block;font-size:11px;padding:2px 6px;border-radius:10px;background:rgba(88,166,255,.15);color:var(--accent);margin-left:6px;}
.param-desc{font-size:12px;color:var(--muted);margin-bottom:10px;line-height:1.5;}
.param-note{font-size:11px;color:var(--warn);margin:-6px 0 10px;line-height:1.4;}
.input-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap;}
.input-row input[type=range]{flex:1;min-width:120px;accent-color:var(--accent);}
.input-row input[type=number]{width:180px;background:var(--code-bg);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:4px 8px;font-size:13px;}
.range-bounds{font-size:11px;color:var(--muted);white-space:nowrap;}
.radio-row{display:flex;gap:16px;}
.radio-row label{display:flex;align-items:center;gap:4px;cursor:pointer;font-size:13px;}
.output-section{background:var(--code-bg);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px;}
.output-section pre{color:var(--ok);font-size:12px;line-height:1.6;white-space:pre-wrap;word-break:break-all;}
.btn{padding:8px 16px;border-radius:6px;border:none;cursor:pointer;font-size:13px;font-weight:500;}
.btn-primary{background:var(--accent);color:#000;}
.btn-secondary{background:var(--surface);color:var(--text);border:1px solid var(--border);}
.btn-danger{background:rgba(248,81,73,.15);color:var(--danger);border:1px solid var(--danger);}
.toolbar{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap;align-items:center;}
.tab-bar{display:flex;gap:4px;margin-bottom:20px;border-bottom:1px solid var(--border);}
.tab{padding:8px 16px;cursor:pointer;color:var(--muted);font-size:13px;border-bottom:2px solid transparent;margin-bottom:-1px;}
.tab.active{color:var(--accent);border-bottom-color:var(--accent);}
.tab-content{display:none;}
.tab-content.active{display:block;}
.warn-box{background:rgba(210,153,34,.1);border:1px solid var(--warn);border-radius:6px;padding:12px 16px;margin-bottom:8px;font-size:12px;color:var(--warn);white-space:pre-line;line-height:1.5;}
.info-box{background:rgba(88,166,255,.1);border:1px solid var(--accent);border-radius:6px;padding:12px 16px;margin-bottom:8px;font-size:12px;color:var(--accent);white-space:pre-line;line-height:1.5;}
@media (max-width:760px){.layout{grid-template-columns:1fr;}.sidebar{position:static;height:auto;}.main{padding:16px;}}
</style>
</head>
<body>
<div class="layout">
  <div class="sidebar">
    <h2>Sections</h2>
    <div id="nav"></div>
    <div style="margin-top:24px">
      <h2 style="margin-bottom:8px">Presets</h2>
      <div id="presets"></div>
      <div class="preset-note">A preset replaces all current values. Presets are starting points, not sizing rules: change one thing, measure, repeat.</div>
    </div>
  </div>
  <div class="main" id="main"></div>
</div>
<script>
const PARAMS = __PARAMS__;
const PRESETS = __PRESETS__;
const WAZUH_VERSION = __VERSION__;
const TARGET = __TARGET__;
const SECTION_KEYS = Object.keys(PARAMS);
const ALL = Object.fromEntries(Object.values(PARAMS).flatMap(s => s.params).map(p => [p.key, p]));
const SLIDER_SPAN = 10000000;  // wider ranges get a number field only
let values = {};

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function getValue(key) {
  return values[key] !== undefined ? values[key] : ALL[key].default;
}

function isChanged(p) {
  const v = getValue(p.key);
  return v !== null && v !== p.default;
}

function changedIn(sid) {
  return PARAMS[sid].params.filter(isChanged).length;
}

function refreshNav() {
  document.querySelectorAll('.nav-item').forEach(b => {
    const c = b.querySelector('.nav-count');
    if (!c) return;
    const n = changedIn(b.dataset.section);
    c.textContent = n ? String(n) : '';
  });
}

function buildNav() {
  const nav = document.getElementById('nav');
  const items = SECTION_KEYS.map(k => [k, PARAMS[k].label.split(' (')[0]])
    .concat([['output', 'Generate config'], ['system', 'Apply and verify']]);
  items.forEach(([id, label], i) => {
    const btn = el('button', 'nav-item' + (i === 0 ? ' active' : ''), label);
    btn.dataset.section = id;
    if (PARAMS[id]) btn.appendChild(el('span', 'nav-count'));
    btn.addEventListener('click', () => showSection(id));
    nav.appendChild(btn);
  });
}

function buildPresets() {
  const cont = document.getElementById('presets');
  Object.entries(PRESETS).forEach(([id, preset]) => {
    const btn = el('button', 'preset-btn', preset.label);
    btn.title = preset.desc;
    btn.addEventListener('click', () => applyPreset(id));
    cont.appendChild(btn);
  });
}

function badgeText(p) {
  const d = p.default === null ? 'auto' : String(p.default);
  if (p.type === 'bool') return 'default ' + d + ', true or false';
  let t = 'default ' + d + ', range ' + p.min + '..' + p.max;
  if (p.gap) t += ' (0 or ' + p.gap + '..)';
  return t;
}

// Clamp to what the daemon accepts: out of range, or inside the gap, stops it at start.
function clampInt(p, v) {
  v = Math.min(p.max, Math.max(p.min, v));
  if (p.gap && v > 0 && v < p.gap) v = p.gap;
  return v;
}

function buildRadio(p, options, val) {
  const row = el('div', 'radio-row');
  options.forEach(o => {
    const lbl = el('label');
    const inp = document.createElement('input');
    inp.type = 'radio';
    inp.name = p.key;
    inp.value = String(o);
    inp.checked = val === o;
    inp.addEventListener('change', () => setVal(p.key, o));
    lbl.appendChild(inp);
    lbl.appendChild(document.createTextNode(' ' + o));
    row.appendChild(lbl);
  });
  return row;
}

function buildParamCard(p) {
  const card = el('div', 'param-card');
  card.id = 'card-' + p.key;
  const keyLine = el('div', 'param-key', p.key);
  keyLine.appendChild(el('span', 'param-badge', badgeText(p)));
  card.appendChild(keyLine);
  card.appendChild(el('div', 'param-desc', p.desc));
  if (p.note) card.appendChild(el('div', 'param-note', 'Note: ' + p.note));

  const val = getValue(p.key);
  if (p.type === 'bool') {
    card.appendChild(buildRadio(p, [true, false], val));
  } else if (p.default !== null && p.min === 0 && (p.max === 1 || p.max === 2)) {
    card.appendChild(buildRadio(p, p.max === 1 ? [0, 1] : [0, 1, 2], val));
  } else {
    const row = el('div', 'input-row');
    const num = document.createElement('input');
    num.type = 'number';
    num.id = 'num-' + p.key;
    num.min = p.min; num.max = p.max; num.step = 1;
    num.value = val === null ? '' : val;
    if (p.default === null) num.placeholder = 'auto (module default)';
    let range = null;
    if (p.default !== null && p.max - p.min <= SLIDER_SPAN) {
      range = document.createElement('input');
      range.type = 'range';
      range.id = 'range-' + p.key;
      range.min = p.min; range.max = p.max; range.value = val;
      range.addEventListener('input', () => {
        const v = clampInt(p, parseInt(range.value, 10));
        num.value = v; setVal(p.key, v);
      });
    }
    num.addEventListener('change', () => {
      if (num.value === '' && p.default === null) { setVal(p.key, null); return; }
      let v = parseInt(num.value, 10);
      if (isNaN(v)) v = p.default;
      v = clampInt(p, v);
      num.value = v; if (range) range.value = v; setVal(p.key, v);
    });
    row.appendChild(el('span', 'range-bounds', String(p.min)));
    if (range) row.appendChild(range);
    row.appendChild(num);
    row.appendChild(el('span', 'range-bounds', String(p.max)));
    card.appendChild(row);
  }
  if (isChanged(p)) card.classList.add('changed');
  return card;
}

function buildSection(sid) {
  const s = PARAMS[sid];
  const div = el('div', 'section');
  div.id = 'section-' + sid;
  const hdr = el('div', 'section-header');
  hdr.appendChild(el('h1', null, s.label));
  hdr.appendChild(el('p', null, s.desc));
  div.appendChild(hdr);
  s.params.forEach(p => div.appendChild(buildParamCard(p)));
  return div;
}

function buildOutputSection() {
  const div = el('div', 'section');
  div.id = 'section-output';
  const hdr = el('div', 'section-header');
  hdr.appendChild(el('h1', null, 'Generate config'));
  hdr.appendChild(el('p', null, 'Deploy the changed-only file. Defaults are compiled into the daemons; a file that repeats every default pins today\\'s values and hides default changes in later releases.'));
  div.appendChild(hdr);

  const toolbar = el('div', 'toolbar');
  const copyBtn = el('button', 'btn btn-primary', 'Copy');
  copyBtn.id = 'copy-btn';
  copyBtn.addEventListener('click', copyConf);
  const dlBtn = el('button', 'btn btn-secondary', 'Download');
  dlBtn.addEventListener('click', downloadConf);
  const resetBtn = el('button', 'btn btn-danger', 'Reset to defaults');
  resetBtn.addEventListener('click', () => applyPreset('default'));
  [copyBtn, dlBtn, resetBtn].forEach(b => toolbar.appendChild(b));
  div.appendChild(toolbar);
  const cross = el('div');
  cross.id = 'cross-out';
  div.appendChild(cross);

  const tabBar = el('div', 'tab-bar');
  [['diff', 'Changed only'], ['conf', 'All parameters (reference)']].forEach(([t, label], i) => {
    const tab = el('div', 'tab' + (i === 0 ? ' active' : ''), label);
    tab.dataset.tab = t;
    tab.addEventListener('click', () => switchTab(t));
    tabBar.appendChild(tab);
  });
  div.appendChild(tabBar);
  ['diff', 'conf'].forEach((t, i) => {
    const tc = el('div', 'tab-content' + (i === 0 ? ' active' : ''));
    tc.id = 'tab-' + t;
    const out = el('div', 'output-section');
    const pre = el('pre');
    pre.id = 'out-' + t;
    out.appendChild(pre);
    tc.appendChild(out);
    div.appendChild(tc);
  });
  return div;
}

function buildSystemSection() {
  const div = el('div', 'section');
  div.id = 'section-system';
  const hdr = el('div', 'section-header');
  hdr.appendChild(el('h1', null, 'Apply and verify'));
  hdr.appendChild(el('p', null, 'Steps and checks for the current values.'));
  div.appendChild(hdr);
  const content = el('div');
  content.id = 'sys-content';
  div.appendChild(content);
  return div;
}

function buildMain() {
  const main = document.getElementById('main');
  SECTION_KEYS.forEach(id => main.appendChild(buildSection(id)));
  main.appendChild(buildOutputSection());
  main.appendChild(buildSystemSection());
  document.getElementById('section-' + SECTION_KEYS[0]).classList.add('active');
}

function showSection(id) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.section === id));
  document.getElementById('section-' + id).classList.add('active');
  if (id === 'output') updateOutput();
  if (id === 'system') updateSystemHints();
}

function setVal(key, val) {
  values[key] = val;
  const card = document.getElementById('card-' + key);
  if (card) card.classList.toggle('changed', isChanged(ALL[key]));
  refreshNav();
}

// Same rules as CROSS in the Python part (keep both in sync).
function crossIssues() {
  const v = k => getValue(k), m = 'wazuh_modules.';
  const out = [];
  if (v('remoted.verify_msg_id') === 1 && v('remoted.worker_pool') > 1)
    out.push(['ERROR', 'remoted.verify_msg_id=1 needs remoted.worker_pool=1 (default 4), remoted exits at start']);
  if (v(m + 'manager_task_delete_timeout') <= v(m + 'manager_task_vd_scan_timeout'))
    out.push(['ERROR', m + 'manager_task_delete_timeout must be greater than manager_task_vd_scan_timeout, modulesd exits at start']);
  if (v(m + 'inventory_sync_server_indexer_sync_max_retry_attempts') === 0 &&
      v(m + 'inventory_sync_server_indexer_sync_max_retry_duration_seconds') === 0)
    out.push(['WARN', 'both inventory sync retry bounds are 0: a persistent indexer failure can pin a flush worker']);
  if (v('remoted.control_keepalive_throttle') >= 450)
    out.push(['WARN', 'remoted.control_keepalive_throttle is at or above half of the default <agents_disconnection_time> (900 s): ' +
      'raise that setting in wazuh-manager.conf above twice the throttle, or healthy agents get marked disconnected']);
  if (v('remoted.auth_max_body_size') >= 10485760)
    out.push(['WARN', 'remoted.auth_max_body_size is 10 MiB or more: if wazuh-manager.conf sets remote.https.max_body_size, keep it ' +
      'above this value, or agents resend oversized requests that get no answer']);
  return out;
}

function showCross(parent) {
  crossIssues().forEach(([level, msg]) => addBlock(parent, 'warn-box', level + ': ' + msg, ''));
}

function generateConf(changedOnly) {
  const lines = ['# ' + TARGET,
                 '# Checked against Wazuh ' + WAZUH_VERSION + ' ranges. This file is per node and never synchronized.', ''];
  let n = 0;
  Object.values(PARAMS).forEach(section => {
    const ps = section.params.filter(p => getValue(p.key) !== null && (!changedOnly || isChanged(p)));
    if (!ps.length) return;
    lines.push('# ' + section.label);
    ps.forEach(p => { lines.push(p.key + '=' + String(getValue(p.key))); n++; });
    lines.push('');
  });
  if (changedOnly && n === 0) return '# No parameter differs from the defaults.';
  return lines.join('\\n');
}

function updateOutput() {
  const box = document.getElementById('cross-out');
  while (box.firstChild) box.removeChild(box.firstChild);
  showCross(box);
  document.getElementById('out-conf').textContent = generateConf(false);
  document.getElementById('out-diff').textContent = generateConf(true);
}

function switchTab(tab) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.toggle('active', t.id === 'tab-' + tab));
}

function copyConf() {
  navigator.clipboard.writeText(generateConf(true) + '\\n').then(() => {
    const btn = document.getElementById('copy-btn');
    btn.textContent = 'Copied';
    setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
  });
}

function downloadConf() {
  const a = document.createElement('a');
  a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(generateConf(true) + '\\n');
  a.download = 'wazuh-manager-internal-options.conf';
  a.click();
}

function applyPreset(id) {
  values = { ...PRESETS[id].values };
  Object.values(ALL).forEach(p => {
    const v = getValue(p.key);
    const range = document.getElementById('range-' + p.key);
    const num = document.getElementById('num-' + p.key);
    if (range && v !== null) range.value = v;
    if (num) num.value = v === null ? '' : v;
    document.querySelectorAll('input[name="' + p.key + '"]').forEach(r => { r.checked = r.value === String(v); });
    const card = document.getElementById('card-' + p.key);
    if (card) card.classList.toggle('changed', isChanged(p));
  });
  refreshNav();
  updateOutput();
  updateSystemHints();
}

function addBlock(parent, cls, label, code) {
  parent.appendChild(el('div', cls, label));
  if (!code) return;
  const out = el('div', 'output-section');
  out.appendChild(el('pre', null, code));
  parent.appendChild(out);
}

const BIN = '/var/wazuh-manager/bin/';
const LOG = '/var/wazuh-manager/logs/wazuh-manager.log';

function updateSystemHints() {
  const cont = document.getElementById('sys-content');
  while (cont.firstChild) cont.removeChild(cont.firstChild);
  const changed = Object.values(ALL).filter(isChanged);
  showCross(cont);

  addBlock(cont, 'info-box',
    '1. Back up the current file, then install the changed-only file on every node that needs it. ' +
    'The file is per node: the cluster never synchronizes it.',
    'cp -p ' + TARGET + ' ' + TARGET + '.bak\\n' +
    'install -o root -g wazuh-manager -m 640 wazuh-manager-internal-options.conf ' + TARGET);
  addBlock(cont, 'info-box',
    '2. Check before restarting. The checker emulates both parsers; wazuh-manager-control check runs every daemon\\'s -t ' +
    'without starting or stopping anything.',
    'python3 wazuh5-tuner.py --check ' + TARGET + '\\n' + BIN + 'wazuh-manager-control check');
  addBlock(cont, 'info-box',
    '3. Restart and confirm every daemon is running and none logged a rejected value.',
    'systemctl restart wazuh-manager\\n' + BIN + 'wazuh-manager-control status\\n' +
    'grep -E "\\\\(2302\\\\)|Invalid definition|Invalid value for key|File descriptor limit" ' + LOG + ' | tail');

  const fdKeys = Object.keys(ALL).filter(k => k.endsWith('.rlimit_nofile'));
  const fdChanged = changed.filter(p => fdKeys.includes(p.key));
  if (fdChanged.length) {
    const procs = {remoted: 'wazuh-manager-remoted', wazuh_db: 'wazuh-manager-db', wazuh_modules: 'wazuh-manager-modulesd'};
    const cmds = fdKeys.map(k => 'grep "Max open files" /proc/$(cat /var/wazuh-manager/var/run/' + procs[k.split('.')[0]] + '-*.pid)/limits   # expect ' + getValue(k));
    const high = fdChanged.some(p => getValue(p.key) > 65536);
    addBlock(cont, high ? 'warn-box' : 'info-box',
      'Open file limits: each daemon raises its soft limit, capped by the hard limit it inherits. The service unit sets ' +
      'LimitNOFILE=65536; above that the daemon keeps the hard limit and logs "File descriptor limit is ...". ' +
      (high ? 'A value above 65536 needs a drop-in that raises LimitNOFILE (or container ulimits) first. ' : '') +
      'The engine (analysisd) asks for a fixed 8192.',
      (high ? 'systemctl edit wazuh-manager   # [Service] LimitNOFILE=<value>\\nsystemctl daemon-reload\\n' : '') + cmds.join('\\n'));
  }

  if (getValue('wazuh.thread_stack_size') !== ALL['wazuh.thread_stack_size'].default) {
    addBlock(cont, 'warn-box',
      'wazuh.thread_stack_size: no daemon -t checks it, so wazuh-manager-control check passes even when it is wrong. ' +
      'The tuner keeps it in range; virtual memory grows by (value - 8192) KiB per thread.', '');
  }

  if (changed.some(p => p.key.endsWith('.debug') && getValue(p.key) > 0)) {
    addBlock(cont, 'warn-box', 'Debug is on. Revert to 0 after the test: debug output fills ' + LOG + ' quickly.', '');
  }

  if (changed.some(p => /^(fim|syscollector|sca)\\./.test(p.key))) {
    addBlock(cont, 'info-box',
      'Inventory limits reach 5.x agents in the startup answer. Set the same values on every node so agents get the same caps after a reconnect.', '');
  }

  addBlock(cont, 'info-box',
    '4. Rollback: restore the backup and restart.',
    'install -o root -g wazuh-manager -m 640 ' + TARGET + '.bak ' + TARGET + '\\nsystemctl restart wazuh-manager');
}

buildNav();
buildPresets();
buildMain();
refreshNav();
</script>
</body>
</html>"""


def render_page():
    return (HTML_TEMPLATE
            .replace("__PARAMS__", json.dumps(PARAMS))
            .replace("__PRESETS__", json.dumps(PRESETS))
            .replace("__VERSION__", json.dumps(WAZUH_VERSION))
            .replace("__TARGET__", json.dumps(TARGET)))


class Server(ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer.server_bind() calls socket.getfqdn(), which can block for seconds on reverse DNS.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj), "application/json")

    def do_GET(self):
        if self.path == "/":
            self._send(200, render_page(), "text/html; charset=utf-8")
        elif self.path == "/api/params":
            self._json(200, PARAMS)
        elif self.path == "/api/presets":
            self._json(200, PRESETS)
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path not in ("/api/generate", "/api/check"):
            return self._json(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > 65536:
            return self._json(413, {"error": "request too large"})
        body = self.rfile.read(length)
        if self.path == "/api/check":
            findings = check_text(body.decode("utf-8", errors="replace"))
            return self._json(200, {"findings": [{"level": l, "line": n, "message": m} for l, n, m in findings]})
        try:
            data = json.loads(body or b"{}")
            values = data.get("values", {})
            if not isinstance(values, dict):
                raise ValueError
        except (ValueError, AttributeError):
            return self._json(400, {"error": "body must be JSON: {\"values\": {key: value}}"})
        clean, errors = validate(values)
        if errors:
            return self._json(400, {"errors": errors})
        self._json(200, {"config": generate(clean, changed_only=data.get("changed_only", True) is not False)})

    def log_message(self, fmt_, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt_ % args))


def main():
    ap = argparse.ArgumentParser(description="Wazuh 5 manager wazuh-manager-internal-options.conf tuner")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default 127.0.0.1; the UI has no authentication)")
    ap.add_argument("--port", type=int, default=7438)
    ap.add_argument("--check", metavar="FILE",
                    help="check a wazuh-manager-internal-options.conf the way both parsers read it, exit 1 on errors")
    args = ap.parse_args()
    if args.check:
        sys.exit(check_file(args.check))
    server = Server((args.host, args.port), Handler)
    print(f"wazuh5-tuner on http://{args.host}:{args.port}/ (Wazuh {WAZUH_VERSION} parameters)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
