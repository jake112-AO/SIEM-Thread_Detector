# SIEM Project — Week 1: Environment Setup

Goal: get Elasticsearch, Logstash, Kibana, and Filebeat running together in
Docker, with a verified path from a log file on disk → Filebeat → Logstash →
Elasticsearch → visible in Kibana. Nothing about detection yet — this is
purely "the pipe doesn't leak."

## Prerequisites

- Docker + Docker Compose installed (`docker compose version` should work)
- At least 4GB RAM free for Docker (Elasticsearch alone wants ~1GB heap)
- Ports free on host: 9200, 5601, 5044, 9600

## 1. Start the stack

```bash
cd siem-week1
docker compose up -d
```

First boot takes a few minutes (pulling ~3 images). Watch it:

```bash
docker compose ps
docker compose logs -f elasticsearch
```

Wait until `es01` health shows `healthy`:

```bash
docker compose ps
```

## 2. Verify Elasticsearch is up

```bash
curl http://localhost:9200
```

You should get a JSON blob with `"cluster_name"` and version info. If this
fails, nothing downstream will work — fix this first.

## 3. Verify Kibana is up

Open http://localhost:5601 in a browser. It may take 30–60s after ES is
healthy. You should see the Kibana home/setup screen — no need to configure
anything yet.

## 4. Drop a test log and confirm ingestion

```bash
mkdir -p logs
echo '{"timestamp":"2026-07-24T12:00:00Z","user":"jiahao","src_ip":"10.0.0.5","action":"login","result":"success"}' >> logs/test.log
```

Filebeat is watching `./logs` (mounted at `/var/log/siem` in the container).
Within a few seconds it should ship this to Logstash → Elasticsearch.

Check it landed:

```bash
curl "http://localhost:9200/siem-generic-*/_search?pretty"
```

You should see your test event back. If you see `index_not_found_exception`,
give it 10–15 more seconds and retry — first-write index creation isn't
instant.

## 5. Confirm in Kibana

Kibana → Stack Management → Data Views → create a data view pattern
`siem-*` with time field `@timestamp`. Then go to Discover and you should
see the test event.

## Troubleshooting

- **Elasticsearch exits immediately / "max virtual memory areas too low"**
  (common on Linux hosts): run once on the host —
  `sudo sysctl -w vm.max_map_count=262144`
- **Filebeat container restarts / permission errors on filebeat.yml**: the
  file must not be world-writable — `chmod go-w filebeat/filebeat.yml`
- **No data reaching Elasticsearch**: check each hop in order —
  `docker compose logs filebeat` (is it reading the file?),
  `docker compose logs logstash` (is it receiving beats input on 5044?),
  then the `_search` query above.
- **Port already in use**: something else on your machine is using
  9200/5601/5044 — stop it or remap the port in `docker-compose.yml`.

## What's next (Week 1, later tasks)

This gets you the empty pipe. Next up in your plan: pull in real CICIDS-2017
CSVs / Zeek logs, get them landing in their own indices (`siem-zeek-*`,
`siem-cicids-*`), and write your first custom Python script that emits
synthetic auth events as ndjson into `logs/`. Don't touch Sigma or
correlation until ingestion for at least two distinct log sources is
verified end-to-end — detection rules on an unverified pipe just waste
debugging time later.

## Shutting down / resetting

```bash
docker compose down          # stop, keep data
docker compose down -v       # stop and wipe Elasticsearch data volume
```
