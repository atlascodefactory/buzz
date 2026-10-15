# Independent Git object storage

By default, Git continues to use the media S3 connection. Deployments may select
an independent Git backend with `BUZZ_GIT_S3_ENDPOINT`, `BUZZ_GIT_S3_ACCESS_KEY`,
`BUZZ_GIT_S3_SECRET_KEY`, `BUZZ_GIT_S3_BUCKET`, `BUZZ_GIT_S3_REGION` and
`BUZZ_GIT_S3_ADDRESSING_STYLE` (`path` or `virtual`). All six settings must be
present and nonempty when any is set. Partial overrides fail startup; they never
borrow media credentials for a different endpoint. Debug output redacts keys.

This supports managed media storage whose conditional overwrite semantics do not
meet the Git manifest-pointer CAS contract. The Git conformance probe remains
unchanged and enabled; it checks the selected Git backend before serving traffic.
Media upload/download authentication, membership checks and limits are unchanged.

When separating an existing mixed bucket, retain the Git backend and its objects
in place. Copy and verify the media contents before changing the media endpoint.
Existing object keys and public relay media URLs must remain unchanged. Configure
and verify backups for **both** backends. The optional override does not migrate
objects, enable public access, create buckets or disable any startup gate.

The focused configuration tests cover default compatibility, every partial
combination, complete overrides, invalid endpoint/style values, redacted debug
output and the actual Config resolver consumed by AppState. Runtime acceptance
must independently verify media transfer and the Git CAS startup probe.
