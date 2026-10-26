#!/bin/sh
# Start a mining node. The wallet is generated inside the container on first start and
# kept in the /data volume, so no key material ever lives in the repository or the image.
set -eu
WALLET=/data/wallet.json
if [ ! -f "$WALLET" ]; then
  forkchain wallet --wallet "$WALLET" new
fi
ADDRESS=$(forkchain wallet --wallet "$WALLET" address)
exec forkchain node \
  --name "$NODE_NAME" \
  --host 0.0.0.0 --port 8333 --advertise-host "$NODE_NAME" \
  --rpc-host 0.0.0.0 --rpc-port 8332 \
  --mine --address "$ADDRESS" --hashrate "${HASHRATE:-20000}" \
  "$@"
