# Maintaining the Chongyejia Casdoor fork

## Source and release boundaries

The current upstream baseline is Casdoor **v4.13.0**, commit
`c9adca039f3c24b570567e0def8d1018e9194c9f`. The maintained upgrade branch is
`codex/casdoor-fork-v4.13.0-integration`. The historical `master` branch has not
yet integrated this upgrade. A branch name, successful source build, or local
checkout does not identify a deployed version.

Keep one product source of truth in this fork. Any internal delivery mirror
must record the exact originating commit. Record source SHA, dependency locks,
base images, final image digest, configuration revision and database migration
for each release. Keep environment credentials and local acceptance receipts
outside the public source history.

## Custom compatibility changes

| Change | Contract to preserve |
| --- | --- |
| Lark provider identity and mini program token flow | Existing identity keys, organization scope, disabled-user and application rejection |
| Explicit passwordless master grant compatibility | Opt-in application and organization, correct confidential client authentication and master password; MFA and disabled-user rejection |
| ID token session lookup for introspection | Explicit ID token hints only, existing access/refresh lookup and persisted revocation state |
| Frontend build promotion | Every local HTML entry asset must exist; invalid builds must retain the previous build |

Each custom change must retain an isolated positive and negative regression.
Avoid unrelated formatting or generated-file changes when integrating upstream.
Business authorization rules belong in the permission service and consumers
where feasible, rather than in Casdoor account storage or identity mapping.

## Updating upstream

1. Review official releases and security fixes weekly; evaluate a stable-tag
   integration monthly. Urgent security fixes receive a separate prompt review.
2. Record the exact target tag/commit and read its release notes, schema changes,
   authentication changes and the custom compatibility diff.
3. Prepare a dedicated `codex/upgrade-*` branch from the maintained product
   branch. Merge the selected upstream stable tag, resolve conflicts against
   the intended contracts and open a pull request. Preserve published history.
4. Run the identity and frontend regressions, build from the committed source,
   and verify the exact image and configuration in TEST. Test affected SDKs and
   consumers against their actual pinned versions.
5. Promote only an accepted, versioned joint release. Production requires its
   explicit environment/configuration authorization and recovery evidence;
   include `oms-auth-service` and affected consumers. Source synchronization
   alone does not authorize deployment.

The release suite covers stable user IDs, owner/organization scope, Lark
identity, authorization code/PKCE, issuer/audience/signature/expiry, refresh and
logout, role withdrawal, tenant isolation and password format compatibility.
The selected logout policy permits existing access tokens until expiry and
immediately rejects refresh or new cross-application session minting.

Before database migrations, preserve a verified backup and recovery path.
An application rollback must preserve users, relationships and roles created
after the upgrade; never replace live configuration with a whole TEST export.
