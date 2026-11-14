#!/bin/bash
cd /workspace/agentgames
while true; do
  pgrep -f "node src/server.js" >/dev/null || (nohup npm start >> /tmp/agent.log 2>&1 &)
  pgrep -f "ngrok http 8787" >/dev/null || (nohup ngrok http 8787 --url=https://daffodil-dismantle-helper.ngrok-free.dev --log=stdout >> /tmp/ngrok.log 2>&1 &)
  sleep 20
done
