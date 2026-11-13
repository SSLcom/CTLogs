# SSL.com Apollo

## Policy

These logs accept TLS certificates and their precertificates, submitted through `add-chain` or `add-pre-chain`, when:

- the chain verifies to one of the [accepted roots](../../tsv/apollo-ca-roots.tsv);
- the notAfter falls inside the shard's expiry range;
- the leaf contains the id-kp-serverAuth Extended Key Usage (these logs are TLS-only).

They reject expired certificates. Chains using SHA-1 signatures are accepted.

**Accepted roots** are every root in Apple's trust store, and every root the Chrome, Microsoft or Mozilla root programs trust for server authentication, as listed in CCADB. The list is synced from CCADB daily.

**Root removal:** a root that leaves CCADB stays accepted until every shard that was open on that day has ended. A root is removed sooner only for a specific reason, such as key compromise or a CA flooding the log, and that is announced on [ct-policy@chromium.org](https://groups.google.com/a/chromium.org/g/ct-policy) first.

Under heavy load the logs answer `429 Too Many Requests`; submitters should retry with backoff.

## Contact

[ctlogs@ssl.com](mailto:ctlogs@ssl.com), monitored continuously. Incidents are acknowledged within one business day.

## Status

The first temporally-sharded Apollo logs are applying for inclusion in the Chrome and Apple CT log programs.

## Active log shards

| URL Prefix | Expiry Range<br>Start | Expiry Range<br>End | Public Key (base64) |
|------------|-----------------------|---------------------|---------------------|
| https://{log,mon}.apollo.ct.ssl.com/2027h1/ | 2027-01-01T00:00:00Z | 2027-06-30T23:59:59Z | `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQc`<br>`DQgAEheHl9fk96mWRtpdnHJl9AuBX9J`<br>`oCCCbCeNaieRvr2gedrBm6GkwFwR/l1`<br>`xowqmh92Uh/J13p4whgNiNYI2ni9w==` |
| https://{log,mon}.apollo.ct.ssl.com/2027h2/ | 2027-07-01T00:00:00Z | 2027-12-31T23:59:59Z | `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQc`<br>`DQgAEWksEJFuR9SQAulvRyoGynpq7Vi`<br>`dve53F0H33JnAyX5pro0oND6wAW9Nkn`<br>`2kSY+deJmR/gm1Gg2n0OAVSs5vfsg==` |
| https://{log,mon}.apollo.ct.ssl.com/2028h1/ | 2028-01-01T00:00:00Z | 2028-06-30T23:59:59Z | `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQc`<br>`DQgAEOG/kpuR9Vqy5AsdFem8e31vn9x`<br>`pgQZ8VsMlIjF7BnLIM+yR1dn1Z59Mur`<br>`XTQo/hKuoLcJ5rlmEGNqNyFPES7MQ==` |
| https://{log,mon}.apollo.ct.ssl.com/2028h2/ | 2028-07-01T00:00:00Z | 2028-12-31T23:59:59Z | `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQc`<br>`DQgAEXxK5dQrpRvs67Ht4U/WPXDeEwU`<br>`w6KlmjF7JxvIkbsFUjGghsGrrlVq3SD`<br>`2F3SVxJFZAHNoVU7g2zz61ygzaPtg==` |

`log.` is the submission prefix and `mon.` the monitoring prefix.

## Inactive log shards

| URL Prefix | Expiry Range<br>Start | Expiry Range<br>End | Public Key (base64) |
|------------|-----------------------|---------------------|---------------------|
