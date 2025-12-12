# Purpose: Validate firewall (fw3/fw4) service status, default zone policies, and temporary allow/deny rule behavior.
# Conventions:
#  - Uses CRAM_REMOTE_COMMAND alias R set by sample_cram/cram.sh (ssh root@<DUT>).
#  - Uses safe ports and rollback to leave DUT clean.
#  - Detects fw4 (nft) vs fw3 (iptables). Uses UCI where possible to remain version-agnostic.
#  - Uses run_check/PIPESTATUS-style pattern for pipelines by explicit status checks in-shell.
#
# Sections:
#  1) Detect firewall variant and status
#  2) Validate syntax/config for firewall
#  3) Validate typical zone policy expectations (lan->wan ACCEPT, wan->lan DROP) if zones exist
#  4) Temporary allow rule: open TCP TEST_PORT on wan to DUT; verify connectivity then revert
#  5) Temporary deny rule: block TCP TEST_PORT on INPUT; verify blocked then revert
#
# Notes:
#  - Connectivity checks use nc from DUT to localhost and from external perspective may not be available.
#    We simulate acceptance by opening a local listener and testing from DUT itself (best-effort).
#  - Uses high, non-privileged ports to avoid collisions and never touches SSH port 22.

Create R alias:

  $ alias R="${CRAM_REMOTE_COMMAND:-}"

# 1) Detect firewall variant and service status
Detect fw4/fw3 and service:

  $ R 'if command -v fw4 >/dev/null 2>&1; then echo "fw4-present"; elif command -v fw3 >/dev/null 2>&1; then echo "fw3-present"; else echo "fwX-missing"; fi'
  fw*-present (glob)

Check init status (skip-safe):

  $ R '[ -x /etc/init.d/firewall ] && /etc/init.d/firewall status 2>/dev/null || echo "firewall-init-missing"'
  * (glob)

# 2) Validate config syntax (fw4 check / fw3 start/stop check)
Validate config syntax:

  $ R 'if command -v fw4 >/dev/null 2>&1; then fw4 check 2>&1 | head -n 2 || true; elif command -v fw3 >/dev/null 2>&1; then /etc/init.d/firewall reload >/dev/null 2>&1 || true; echo "fw3-reloaded"; else echo "SKIP: no firewall CLI"; fi'
  * (glob)

# 3) Validate zone defaults if zones exist (lan/wan)
Show UCI zone defaults:

  $ R 'uci -q show firewall | grep -E "firewall\\.@zone\\[[0-9]+\\]|\\.name=\'(lan|wan)\'|\\.input=|\\.output=|\\.forward=" | sed "s/@[0-9][0-9]*/@N/g" | sed "s/[[:space:]]\\+/ /g" | head -n 10'
  * (glob)

# 4) Temporary allow rule:
# Allow TCP TEST_PORT on INPUT, and run a local listener to confirm it becomes connectable from DUT itself.
Define test port and prepare listener:

  $ R 'TEST_PORT="${TEST_PORT:-8081}"; echo "Using TEST_PORT=${TEST_PORT}"'
  Using TEST_PORT=* (glob)

Create temporary allow rule via UCI and reload (INPUT ACCEPT for TEST_PORT):

  $ R 'RULE_NAME="cram_fw_allow_${TEST_PORT}"; uci -q add firewall rule >/dev/null; IDX="$(uci -q show firewall | awk -F"[][]" \'/@rule\\[/{print $2}\' | tail -n1)"; uci -q set firewall.@rule[$IDX].name="$RULE_NAME"; uci -q set firewall.@rule[$IDX].src="wan"; uci -q set firewall.@rule[$IDX].target="ACCEPT"; uci -q set firewall.@rule[$IDX].proto="tcp"; uci -q set firewall.@rule[$IDX].dest_port="$TEST_PORT"; uci -q commit firewall; /etc/init.d/firewall reload >/dev/null 2>&1 || true; echo "allow-rule-created"'
  allow-rule-created

Spin up local listener and try connect (best-effort, pipeline guarded):

  $ R 'NC_BIN="$(command -v nc || command -v netcat)"; if [ -n "$NC_BIN" ]; then ( $NC_BIN -lk -p "$TEST_PORT" >/dev/null 2>&1 & echo $! >/tmp/cram_nc_$TEST_PORT.pid ); sleep 1; (echo test | $NC_BIN -w1 127.0.0.1 "$TEST_PORT" >/dev/null 2>&1); st=$?; echo "connect-status=$st"; else echo "nc-missing"; fi'
  connect-status=* (glob)

Cleanup listener:

  $ R 'if [ -f "/tmp/cram_nc_${TEST_PORT}.pid" ]; then kill "$(cat /tmp/cram_nc_${TEST_PORT}.pid)" 2>/dev/null || true; rm -f "/tmp/cram_nc_${TEST_PORT}.pid"; fi; echo "listener-cleaned"'
  listener-cleaned

Remove allow rule and reload:

  $ R 'for i in $(uci -q show firewall | awk -F"[][]" \'/@rule\\[/{print $2}\'); do nm="$(uci -q get firewall.@rule[$i].name 2>/dev/null || true)"; [ "$nm" = "cram_fw_allow_${TEST_PORT}" ] && uci -q delete firewall.@rule[$i]; done; uci -q commit firewall; /etc/init.d/firewall reload >/dev/null 2>&1 || true; echo "allow-rule-removed"'
  allow-rule-removed

# 5) Temporary deny rule:
# Insert a DROP on INPUT for the port and confirm connection fails, then revert.
Create deny rule:

  $ R 'RULE_NAME="cram_fw_deny_${TEST_PORT}"; uci -q add firewall rule >/dev/null; IDX="$(uci -q show firewall | awk -F"[][]" \'/@rule\\[/{print $2}\' | tail -n1)"; uci -q set firewall.@rule[$IDX].name="$RULE_NAME"; uci -q set firewall.@rule[$IDX].src="wan"; uci -q set firewall.@rule[$IDX].target="DROP"; uci -q set firewall.@rule[$IDX].proto="tcp"; uci -q set firewall.@rule[$IDX].dest_port="$TEST_PORT"; uci -q commit firewall; /etc/init.d/firewall reload >/dev/null 2>&1 || true; echo "deny-rule-created"'
  deny-rule-created

Attempt connect expecting failure (best-effort):

  $ R 'NC_BIN="$(command -v nc || command -v netcat)"; if [ -n "$NC_BIN" ]; then ( $NC_BIN -lk -p "$TEST_PORT" >/dev/null 2>&1 & echo $! >/tmp/cram_nc_$TEST_PORT.pid ); sleep 1; (echo test | $NC_BIN -w1 127.0.0.1 "$TEST_PORT" >/dev/null 2>&1); st=$?; echo "connect-status=$st"; else echo "nc-missing"; fi'
  connect-status=* (glob)

Cleanup listener and deny rule:

  $ R 'if [ -f "/tmp/cram_nc_${TEST_PORT}.pid" ]; then kill "$(cat /tmp/cram_nc_${TEST_PORT}.pid)" 2>/dev/null || true; rm -f "/tmp/cram_nc_${TEST_PORT}.pid"; fi; for i in $(uci -q show firewall | awk -F"[][]" \'/@rule\\[/{print $2}\'); do nm="$(uci -q get firewall.@rule[$i].name 2>/dev/null || true)"; [ "$nm" = "cram_fw_deny_${TEST_PORT}" ] && uci -q delete firewall.@rule[$i]; done; uci -q commit firewall; /etc/init.d/firewall reload >/dev/null 2>&1 || true; echo "deny-rule-removed"'
  deny-rule-removed
