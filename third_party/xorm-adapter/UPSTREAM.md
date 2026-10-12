# Local xorm adapter extension

Source: github.com/casdoor/xorm-adapter/v3, v3.1.0, Apache-2.0.
The upstream adapter.go, go.mod, go.sum and LICENSE are preserved byte-for-byte.
The parent module pins this directory with a replace directive.

Only existing_table.go adds two explicit entry points: open an existing policy
table without schema synchronization, and save policies transactionally without
DROP/CREATE. Existing upstream constructors and methods remain unchanged.
These exports do not enable a new Casdoor startup mode on their own.

Existing-table bulk saves require an exclusive policy writer; a transaction alone
does not serialize independent Casbin enforcer caches. Live multiwriter acceptance
and exact MySQL fault tests remain part of release acceptance.
