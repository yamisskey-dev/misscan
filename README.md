# Misscan

Misskey インスタンス向けアンチスパム・セキュリティツールキット

**自分が管理する、または許可を得たインスタンスでのみ使用してください**

## インストール

```bash
cargo build --release
```

## 使い方

```bash
# セキュリティスキャン
misscan scan --target https://example.com

# スパム検出
misscan -i https://example.com -t <TOKEN> detect --timeline

# リアルタイム監視
misscan -i https://example.com -t <TOKEN> monitor

# アカウント分析（管理者権限）
misscan -i https://example.com -t <ADMIN_TOKEN> analyze

# レポート生成
misscan report --target https://example.com -o report.md
```

## 機能 (v0.1.0)

- `scan` - 登録設定、レート制限、APIセキュリティのスキャン
- `detect` - ユーザー/ノート/タイムラインのスパムパターン検出
- `monitor` - 高頻度投稿・大量登録のリアルタイム監視
- `analyze` - アカウント作成パターン分析
- `report` - セキュリティレポート生成

## ロードマップ

### v0.2.0
- カスタムスパムパターン設定
- 日本語スパム対応

### v0.3.0
- Webhook通知（Discord/Slack）
- ブロックリスト生成

### v1.0.0
- 設定ファイル対応
- デーモンモード

## ライセンス

MIT
