# SSL.com Certificate Transparency Logs

Metadata and accepted roots for the [Certificate Transparency](https://certificate.transparency.dev/) logs SSL.com operates.

SSL.com's CT logs are powered by [TesseraCT](https://github.com/transparency-dev/tesseract), which implements the [Static CT API](https://c2sp.org/static-ct-api) on the [Tessera](https://github.com/transparency-dev/tessera) library. They run on AWS: S3 holds the tiles, RDS MySQL the sequencing state, and CloudFront serves the monitoring prefix.

## Mark Certificate logs

[Mercury](crt/mercury) logs accept only Mark Certificates (VMC and CMC) used for [BIMI](https://bimigroup.org/). They are temporally sharded by certificate expiry and are applying for inclusion in the Apple CT log program.

## TLS logs

[Apollo](crt/apollo) logs accept publicly trusted TLS certificates. They are temporally sharded by certificate expiry, in half-year shards, and are applying for inclusion in the Chrome and Apple CT log programs.

## Metadata

| File | Schema | Purpose |
|---|---|---|
| [`json/sslcom-operator.json`](json/sslcom-operator.json) | [operator_list_schema_v1](https://googlechrome.github.io/CertificateTransparency/operator_list_schema_v1.json) | Lists every log below; the URL to give CT log programs |
| [`json/mercury2026.json`](json/mercury2026.json) | [log_schema_v2](https://googlechrome.github.io/CertificateTransparency/log_schema_v2.json) | Mercury 2026 shard |
| [`json/mercury2027.json`](json/mercury2027.json) | [log_schema_v2](https://googlechrome.github.io/CertificateTransparency/log_schema_v2.json) | Mercury 2027 shard |
| [`json/mercury2028.json`](json/mercury2028.json) | [log_schema_v2](https://googlechrome.github.io/CertificateTransparency/log_schema_v2.json) | Mercury 2028 shard |
| [`json/apollo2027h1.json`](json/apollo2027h1.json) | [log_schema_v2](https://googlechrome.github.io/CertificateTransparency/log_schema_v2.json) | Apollo 2027h1 shard |
| [`json/apollo2027h2.json`](json/apollo2027h2.json) | [log_schema_v2](https://googlechrome.github.io/CertificateTransparency/log_schema_v2.json) | Apollo 2027h2 shard |
| [`json/apollo2028h1.json`](json/apollo2028h1.json) | [log_schema_v2](https://googlechrome.github.io/CertificateTransparency/log_schema_v2.json) | Apollo 2028h1 shard |
| [`json/apollo2028h2.json`](json/apollo2028h2.json) | [log_schema_v2](https://googlechrome.github.io/CertificateTransparency/log_schema_v2.json) | Apollo 2028h2 shard |

Accepted roots per log family are in [`pem/`](pem) and [`tsv/`](tsv), one certificate per file in [`crt/<family>/`](crt). Each log's `get-roots` endpoint is authoritative; these files are generated from it.

## Contact

[ctlogs@ssl.com](mailto:ctlogs@ssl.com), monitored continuously. Incidents are acknowledged within one business day.

## Maintaining

Every change goes through a pull request; CI validates it (`scripts/validate.py --live --base <PR base>`). Locally: `pip install --require-hashes -r scripts/requirements.txt`, then `scripts/validate.py --live --base origin/main`.

- **Add a shard:** add `json/<log>.json`, add its raw URL to `json/sslcom-operator.json`, and add a row to `crt/<family>/README.md`.
- **Close a shard:** set its `status` to `readonly` and update `status_timestamp`; move its row to "Inactive log shards".
- **Roots changed:** run `scripts/make_roots.py <family>` once every active shard serves the new set, and commit the result.

Never change a published log's `key`, `log_id`, endpoints or `temporal_interval`: they are its identity, and `--base` fails a change to any of them.
