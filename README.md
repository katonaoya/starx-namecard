## Slack × Render × Dify 連携ボット（Flask）

Slackでボット宛のメンションに画像を添付すると、Webhookサーバーが受信し、画像をSlackから取得してDifyにアップロードします。

### 事前準備（Slack App）
- Bot Token Scopes: `app_mentions:read`, `files:read`, `channels:history`, `chat:write`
- Event Subscriptions: `app_mention` を購読（必要に応じて `message.channels` や `message.im`）
- 後で `Request URL` に `https://<your-render-app>.onrender.com/slack/events` を設定

### 環境変数
`.env`（ローカル）や Render の環境変数として以下を設定してください。

- `SLACK_BOT_TOKEN`（xoxb-...）
- `SLACK_SIGNING_SECRET`（署名検証用・推奨）
- `DIFY_API_KEY`
- `DIFY_API_URL`（例: `https://api.dify.ai/v1/files/upload`）
- `DIFY_USER_ID`（任意・アプリ要件次第）
- `PORT`（任意、デフォルト5000）

ローカル開発では `env.example` を参考に `.env` を作成してください。

### セットアップ（ローカル）
以下のコマンドはユーザー自身で実行してください（自動実行しません）。

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

実行後、`http://localhost:5000/healthz` が `{ "status": "ok" }` を返せば起動成功です。

### Render デプロイ
- Build Command: `pip install -r requirements.txt`
- Start Command: `python app.py`
- 環境変数をダッシュボードに登録（上記と同じ）

### Slack の Request URL 設定
`https://<your-render-app>.onrender.com/slack/events` を設定し、`Verified` になればOK。

### 動作
- Slack のメンションイベントを受け取り、添付ファイルをSlack Web APIでダウンロード
- Difyに `multipart/form-data` の `file` フィールドでアップロード
- 署名検証（`SLACK_SIGNING_SECRET` 設定時）、タイムスタンプ5分以内のみ受理

### 注意
- Difyのエンドポイントはアプリ種別により異なるため、必要に応じて `DIFY_API_URL` を変更してください。


