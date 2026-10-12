#!/usr/bin/env bash
set -euo pipefail

# Called only inside the CI runner's fresh Linux network namespace. Never
# silently fall back to a connected test process if namespace creation fails.
test "$(uname -s)" = Linux
test -n "${CASDOOR_PARENT_NETNS:-}"
test "$(readlink /proc/self/ns/net)" != "$CASDOOR_PARENT_NETNS"
test "$(ip -o link show | awk -F': ' '{print $2}')" = lo
ip link set lo up
test -z "$(ip -4 route show default)"
test -z "$(ip -6 route show default)"
test "${GOPROXY:-}" = off
test "${GOSUMDB:-}" = off
python3 - <<'PY'
import errno, socket
for address in ('192.0.2.1', '198.51.100.1'):
    with socket.socket() as sock:
        sock.settimeout(0.5)
        try:
            sock.connect((address, 9))
        except OSError as error:
            if error.errno not in (errno.ENETUNREACH, errno.EACCES, errno.EPERM):
                raise SystemExit('outbound isolation not proven')
        else:
            raise SystemExit('outbound connection unexpectedly allowed')
print('Fresh loopback-only network namespace verified')
PY

go_test() {
  go test -mod=readonly -race -count=1 -timeout=120s -p=2 -v "$@"
}

go_test ./conf ./object ./authz ./routers -run '^TestBuiltinIsolation(Config|AdministratorBoundary|ProvisioningPayload|ProfileUpdate|UserApi|LegacySdkCreateObject|AppTokenSession)$'
go_test ./util/auditsecret -run '^Test(SupportedBodies|MalformedBodiesFailClosed|NewCasdoorCredentialsAndEncodedNames|URI|OtherCredentialAliases)$'
go_test ./object -run '^TestAuditRecord(EncodedCredentials|MalformedBody)$'
go_test ./idp -run '^TestLegacyLark(ExplicitIDSelection|RejectsMissingSelectedID|RejectsUnconfiguredIDType|UsesAppTokenEndpoint|RejectsInvalidAppTokenResponses|RejectsInvalidOIDCResponses)$'
go_test ./object -run '^Test(LarkMiniProgram(FullTokenFlowRejectsDisabledApplication|FullTokenFlowAllowsScopedActiveUser|FullTokenFlowRejectsSigninPolicies|FullTokenFlowRejectsCrossTenantAndUnreviewedSignup|FullTokenFlowRejectsRequestedScope|FullTokenFlowRejectsExplicitPermissionDeny|RejectsMissingProviderCodeAndIDType|RejectsAmbiguousProviders|RejectsMismatchedSelectedIDBeforeLookup)|TypedLark(IdentityEvidence|UserSelectionRejectsAmbiguityAndCrossOwner)|LegacyLarkUserIdTypeSurvivesProviderConversion)$'
go_test ./object -run '^TestPasswordlessMaster(Grant(ApplicationIsExactAndOptIn|RequiresAuthenticatedClient|RequiresMasterPassword|DoesNotChangeMfaRejection)|PasswordGrant(MintsVerifiedTokens|RequiresBothOptInFlags|RejectsInvalidCredentialsAndUsers))$'
go_test ./object -run '^TestTokenLookupIDSessionHints$'
go_test ./object -run '^TestMigration(DSNOffAndOtherDriversPreserveBytes|DSNPreservesConnectionOptions|LockOptionBounds|DSNRejectsInvalidPrefixWithoutCredentialDisclosure)$'
go_test ./object -run '^TestControlledStartup(LegacyUnchanged|RejectsUnsafeInputs|ManifestBinding|ExclusiveFence|CompletedReceiptBinding|EffectiveConfiguration|FileBounds|ServeGuardsDDL|AdapterScope|DatabaseTargets|NonregularFiles)$'
go_test ./object -run '^TestControlledRuntimeExistingAnchorsNoSeed$'
# Use the root's fixed dependency graph while preserving the upstream module's
# original go.mod/go.sum bytes. Only these three local adapter files are tested.
go_test third_party/xorm-adapter/adapter.go third_party/xorm-adapter/existing_table.go third_party/xorm-adapter/existing_table_test.go -run '^TestExistingTable(RejectsMissingWithoutDDL|SaveAndClearPreserveSchema|InsertFailureRollsBackDelete|DeleteFailurePreservesPolicy|OversizedPolicyFailsBeforeDelete)$'
go_test ./object -run '^TestTokenCleanup(RefreshEligibility|InvalidTimesAndRetention|SQLitePreservesRefreshAndPages|UnsafeRefreshMetadata|ConditionalDelete|RunBounds)$'
go build -mod=readonly -p=2 ./...
