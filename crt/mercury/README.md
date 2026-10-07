# SSL.com Mercury

## Policy

These logs accept only Mark Certificates (VMC and CMC) and their precertificates, submitted through `add-chain` or `add-pre-chain`, when the chain verifies to one of the [accepted roots](../../tsv/mercury-ca-roots.tsv) and:

- the notAfter falls inside the shard's expiry range;
- the leaf is not a CA and has neither keyCertSign nor cRLSign;
- the EKU is exactly id-kp-BrandIndicatorforMessageIdentification (`1.3.6.1.5.5.7.3.31`);
- certificatePolicies include the Mark Certificate policy `1.3.6.1.4.1.53087.1.1`;
- exactly one subject markType (`1.3.6.1.4.1.53087.1.13`) is present: Registered Mark or Government Mark (VMC), or Prior Use Mark, Modified Registered Mark or Provisional Mark (CMC);
- a logotype extension (`1.3.6.1.5.5.7.1.12`) is present.

They reject expired certificates, chains using SHA-1 signatures, and anything that fails the rules above. The accepted roots are the Mark Certificate roots that are currently issuing; we update the list from time to time in accordance with this policy.

## Status

The first temporally-sharded Mercury logs are applying for inclusion in the Apple CT log program in 2026.

## Active log shards

| URL Prefix | Expiry Range<br>Start | Expiry Range<br>End | Public Key (base64) |
|------------|-----------------------|---------------------|---------------------|
| https://{log,mon}.mercury.ct.ssl.com/2026/ | 2026-01-01T00:00:00Z | 2026-12-31T23:59:59Z | `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQc`<br>`DQgAESMidgvn0QuTkoqcX4hrDWaViKV`<br>`Pq9rZ/VLq/6PinMWE1JznhEUOqnzACf`<br>`cx/qjtfUVwLRdoNfS0WE2Qumb21+w==` |
| https://{log,mon}.mercury.ct.ssl.com/2027/ | 2027-01-01T00:00:00Z | 2027-12-31T23:59:59Z | `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQc`<br>`DQgAE1QgX4C/iNbrWKSKKcOrVKIRG3c`<br>`jCx3ggkMpvKJcrTdDUVFitZyoPUMBUk`<br>`aQrqur900z+mSGNXjZz4D0V3aVFSQ==` |
| https://{log,mon}.mercury.ct.ssl.com/2028/ | 2028-01-01T00:00:00Z | 2028-12-31T23:59:59Z | `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQc`<br>`DQgAEeDXzUUKDHSmVFaUt7lZCsL5kZk`<br>`YVFzc/T53yeLzG5H5mEiABa4X1zxOYH`<br>`VnbnuOFKWYenQzmMzp1AZx/yiU+8Q==` |

`log.` is the submission prefix and `mon.` the monitoring prefix.

## Inactive log shards

| URL Prefix | Expiry Range<br>Start | Expiry Range<br>End | Public Key (base64) |
|------------|-----------------------|---------------------|---------------------|
