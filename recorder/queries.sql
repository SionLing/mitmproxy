-- Common queries for traffic.db. Use with:
--   sqlite3 recorder/traffic.db "..."
-- Timestamps are unix epoch; unixepoch() gives the current time in SQLite 3.38+.

-- 1. Latest 50 requests (any host)
SELECT id, datetime(ts, 'unixepoch', 'localtime') AS time, method, host, path, status, duration_ms, resp_size
FROM flows
ORDER BY id DESC
LIMIT 50;

-- 2. Requests to a specific domain (incl. subdomains) in the last hour
SELECT id, datetime(ts, 'unixepoch', 'localtime') AS time, method, path, status, duration_ms, resp_size
FROM flows
WHERE host LIKE '%.example.com' AND ts > unixepoch() - 3600
ORDER BY ts DESC;

-- 3. Per-domain aggregate stats in the last hour
SELECT host,
       count(*)            AS requests,
       sum(resp_size)      AS total_bytes,
       avg(duration_ms)    AS avg_ms,
       sum(status >= 500)  AS errors_5xx,
       sum(status >= 400 AND status < 500) AS errors_4xx
FROM flows
WHERE ts > unixepoch() - 3600
GROUP BY host
ORDER BY requests DESC;

-- 4. Failed requests (HTTP 5xx or connection errors)
SELECT id, datetime(ts, 'unixepoch', 'localtime') AS time, method, host, path, status, error
FROM flows
WHERE (status >= 500 OR error IS NOT NULL) AND ts > unixepoch() - 3600
ORDER BY ts DESC;

-- 5. Slowest requests in the last hour
SELECT id, datetime(ts, 'unixepoch', 'localtime') AS time, method, host, path, status, duration_ms
FROM flows
WHERE ts > unixepoch() - 3600 AND duration_ms IS NOT NULL
ORDER BY duration_ms DESC
LIMIT 20;

-- 6. Full-text search in URL path or bodies
SELECT id, method, host, path, status
FROM flows
WHERE path LIKE '%keyword%'
   OR req_body LIKE '%keyword%'
   OR resp_body LIKE '%keyword%'
ORDER BY id DESC
LIMIT 50;

-- 7. Single flow with full detail (headers + bodies)
SELECT * FROM flows WHERE id = 123;

-- 8. Status code distribution for a domain
SELECT status, count(*) AS n
FROM flows
WHERE host LIKE '%.example.com'
GROUP BY status
ORDER BY n DESC;
