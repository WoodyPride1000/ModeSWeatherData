Hybrid Communication System (HCS)

セキュアP2Pネットワーク通信プロトコル設計書

Rev 3.0（アーキテクチャ確定・スケーラビリティ制約反映版）

# 0. 改訂履歴と本改訂の位置づけ

【重大・最優先】 v2.0 の Pull型 IMediaTransport 確定は誤りだった。実装（UdpTransport, TransportAES256, PBKDF2KeyProvider）はすべて common.h の Push型 Transport インターフェースに基づいて書かれており、Pull型は設計書上の提案のみで実装に一度も採用されていなかった。本書でPush型を正式仕様として再確定する。

# 1. 序論

## 1.1. 目的

本設計書は、HCSプロジェクトで使用されるセキュアなP2Pネットワーク通信レイヤーの実装仕様を定義する。非同期I/Oを基盤とし、メディアデータ用チャネルと制御（トポロジー管理）用チャネルを分離した二重チャネル構成により、機密性・完全性の高いデータ伝送と、低遅延な制御メッセージ交換を両立する。

## 1.2. 解決する課題

標準的なUDP通信は、データグラムの喪失、順序の入れ替わり、および第三者による傍受・改ざんに対する保護を提供しない。本プロトコルはメディアチャネルに対し暗号化と認証を適用することでこれに対処する。加えて、想定端末数（最大1,000台規模）と物理層帯域（64kbps以下）の制約から、制御メッセージの配送方式そのものがスケーラビリティのボトルネックになることが判明しており、本改訂ではこれを正式な設計制約として扱う（4章参照）。

# 2. アーキテクチャとレイヤー構造

【確定】 トランスポート層はPush型で統一する。呼び出し側が受信コールバックを事前登録し（SetReceiveCallback）、データ到着時にトランスポート側から能動的に呼び出す方式。QUIC/TLS1.3への移行は将来課題とし、現行は自前のAES-256-GCM実装（TransportAES256によるデコレータパターン）を正式仕様とする。

【未解決】 QuicNgTcp2Transport（Pull型IMediaTransportの実装として書かれたクラス）の扱いが未確定。中身はQUICを一切使用しておらずAES-GCM+生UDPが実体である一方、common.hのPush型Transportとはインターフェースが非互換。方針候補：(a) 廃棄し、UdpTransport+TransportAES256をメディアチャネルの唯一の実装とする、(b) Push型Transportインターフェースに合わせて全面書き直しする。

# 3. モジュール設計

## 3.1. Endpoint / Transport インターフェース（common.h・正式版）

以下がプロジェクト全体で参照される唯一の正式定義である。以降のクラスはすべてこれに従う。

namespace hcs_net {

struct Endpoint {
    std::string address;   // IPアドレス（IPv4/IPv6）
    uint16_t port;
    std::string ToString() const { return address + ":" + std::to_string(port); }
    bool operator==(const Endpoint&) const;
    bool operator<(const Endpoint&) const;  // map/setキーとして使用可能
};

class Transport {
public:
    virtual ~Transport() = default;
    virtual void Start() = 0;
    virtual void Stop() = 0;
    virtual void Send(const std::vector<uint8_t>& data, const Endpoint& destination) = 0;

    using ReceiveCallback = std::function<void(const std::vector<uint8_t>&, const Endpoint&)>;
    virtual void SetReceiveCallback(ReceiveCallback callback) = 0;  // 値渡し1本に統一
};

} // namespace hcs_net

【注】 SetReceiveCallback は当初コピー版／ムーブ版の2オーバーロードで実装されていたが、値渡し1本（pass-by-value-then-move）に統一する。呼び出し側がlvalue/rvalueいずれを渡しても最適に動作し、実装クラス側の重複実装を避けられる。

## 3.2. KeyProvider インターフェース

【確定】 メソッド名は GetEncryptionKey() / GetSalt()（ともに const std::vector<uint8_t>& を返す）に統一する。過去に実装で使われていた GetMasterKey()/GetMasterSalt()、および非純粋仮想・固定ダミー値を返す旧 hcs_control::KeyProvider は廃止する。

class KeyProvider {
public:
    virtual ~KeyProvider() = default;
    [[nodiscard]] virtual const std::vector<uint8_t>& GetEncryptionKey() const = 0;
    [[nodiscard]] virtual const std::vector<uint8_t>& GetSalt() const = 0;
};

【未解決】 旧 hcs_control::KeyProvider は非純粋仮想でダミーキー(0xAA固定)を返す実装がデフォルトになっており、オーバーライド忘れが検知されない危険な設計だった。正式版（上記）は純粋仮想化により解消したが、テスト用ダミー実装（例: InsecureDummyKeyProvider）を本番コードから隔離する運用ルールを別途定める必要がある。

## 3.3. PBKDF2KeyProvider（実装）

共有パスフレーズとソルトから PBKDF2-HMAC-SHA256 により鍵を導出する。

【未解決】 導出された鍵・ソルトはプロセス終了/デストラクト時にメモリ上でゼロクリアされていない（OPENSSL_cleanse等の未使用）。鍵がスワップやメモリダンプ経由で漏洩するリスクがあるため、デストラクタでの明示的ゼロ化を追加すべき。

## 3.4. TransportAES256（暗号化デコレータ）

Transport をラップし、送受信データを AES-256-GCM で暗号化・復号する。データグラム構造は IV(12B) + Ciphertext + Tag(16B)。

【重大・最優先】 GCM Nonce（IV）の生成方式に重大な脆弱性がある。IVは「全ノード共通の固定4バイトプレフィックス + プロセス起動時にランダム化される64bitカウンタ（実効エントロピーは32bit程度）」で構成されている。PBKDF2KeyProviderが共有パスフレーズから鍵を導出する設計上、メッシュ内の複数ノードが同一のAES鍵を持つ可能性が高く、その場合「同一鍵・同一IV」の衝突が現実的な確率で発生する。GCMは鍵とIVの組が一度でも重複すると、認証鍵の復元や平文のXOR漏洩など暗号化・認証の両方が破綻する。対策方針は未決定。候補：(a) ノードごとに一意なセッション鍵をECDH等で都度導出し、共有パスフレーズ由来の鍵を長期間使い回さない、(b) カウンタを永続化しプロセス再起動をまたいで単調増加を保証する、(c) IVの固定プレフィックス部にノード固有IDを埋め込みノード間での衝突を防ぐ。

【重大・最優先】 Send() 呼び出し時に use-after-free の危険がある。TransportAES256::Send は暗号化結果をローカル変数として生成し base_transport_->Send() に渡すが、UdpTransport::Send の非同期送信（async_send_to）はこの呼び出しが返った後も継続してバッファを参照する。呼び出し元のローカル変数は Send() が return した時点で破棄されるため、非同期送信が実際にバッファを読み取る時点で解放済みメモリを参照する未定義動作となる。対策：Send/SetReceiveCallback 系のシグネチャをムーブ渡し（std::vector<uint8_t> data）に変更し、実装側（UdpTransport）が非同期操作完了までデータの所有権を保持する（例: shared_ptr<vector<uint8_t>>でラップしラムダにキャプチャ）。

## 3.5. UdpTransport（生トランスポート実装）

Boost.Asio による非同期UDP送受信を行う。Transport インターフェースを実装する。3.4節で述べた use-after-free 修正の適用対象。

## 3.6. TopologyManager（トポロジー管理）

ピアディスカバリ、親ノード選定、ヘルスチェックを担当する。

【未解決】 ノードの一意識別に IPアドレスを主キーとして使用している（neighbor_nodes_: map<string, PeerState>、キーはIP）。HCSNode側は self_node_id_ という永続的なノードIDを持つ設計だが、TopologyManagerにはnode_idの概念が存在しない。DHCP環境やNAT配下では同一ノードのIPが変化/衝突しうるため、node_idを主キーとするモデルへの変更を検討要。AdvertiseMessageにもnode_idフィールドを追加する必要がある。

【未解決】 親ノードタイムアウト検知後（CheckParentHealth）、次点候補ノードへの即時再選定ロジックがない。次の親確定は次のADVERTISE受信を待つのみで、空白期間が生じる。

【未解決】 neighbor_nodes_ のプルーニング（離脱ノードの削除）が未実装で、稼働時間に応じて無制限に肥大化する。

【未解決】 is_parent フラグを true にセットする箇所が実装中に存在しない（実質デッドコード）。

【未解決】 ComputeNodeScore の重み係数（hop_count×10, bandwidth×5, stability×2, rtt×0.1）が実測データに基づかないハードコード値。特にrtt項は無線メッシュ環境でRTTが大きい場合に支配的になりうる。

【未解決】 neighbor_nodes_ / best_scores_ に対するマルチスレッドアクセスの排他制御（mutex等）が未実装。HCSNode::Start()は別スレッド実行を想定しており、競合の可能性がある。

# 4. スケーラビリティ制約（新設）

想定端末数（最大1,000台規模）と物理層帯域（64kbps以下）を前提に、制御メッセージ（ADVERTISEプローブ）の配送方式が成立するかどうかを検証した。結論として、フラット・マルチキャスト方式は約127台が上限であり、1,000台規模には階層化トポロジーが必須である。

## 4.1. 想定通信モデルとプローブパケットサイズ

通信方式: マルチキャスト（同一リンク内の全ノードへ配信）。周期: 5秒に1回。

## 4.2. 64kbps制約下での許容ノード数試算

マルチキャスト方式では、送信総量と個々のノードの受信負荷がほぼ一致する点に注意が必要である。あるノードは自ノード以外の (N-1) 台分のプローブを毎周期受信する。

受信負荷(bps) = (N - 1) × 158bytes × 8bit / 5sec

N=4:     3 × 1,264 / 5 ≈ 758 bps        （64kbps比 約1.2%、問題なし）
N=1000:  999 × 1,264 / 5 ≈ 252,300 bps  ≈ 252.3 kbps （64kbps比 約394%、超過）

【重大・最優先】 N=1,000 の受信負荷は64kbpsリンクの約4倍に達し、物理的に成立しない。さらに実運用ではCSMA/CA等の衝突回避オーバーヘッドや半二重制約により実効容量は公称値より30〜50%程度低く、非マルチキャストネイティブな無線方式（フラッディング代替が必要な場合）ではさらに数倍に悪化しうる。以下の試算はあくまで楽観的な下限値である。

安全マージンを容量の50%とした場合の上限ノード数:

(N - 1) × 1,264 / 5 ≤ 0.5 × 64,000
N - 1 ≤ 126.6
N ≤ 約127台

## 4.3. 階層化設計（必須要件）

1,000台規模を実現するため、以下を設計上の必須要件とする。

ネットワークを100台程度を上限とする複数グループに分割し、プローブのマルチキャスト範囲をグループ内に限定する。

グループ間の通信は、選出された少数の親/ゲートウェイノードを介したユニキャストに限定し、マルチキャストを用いない。

グループサイズの上限値は、4.2節の計算式にパケットサイズ・周期・実効帯域（安全マージン込み）を代入して運用時に再算出できるようにする（固定値として設計書に埋め込まない）。

【未解決】 グループ分割の具体的アルゴリズム（地理的近接性、RSSI、初期登録順など何を基準にグループを割り当てるか）が未設計。TopologyManagerの拡張が必要。

## 4.4. パラメータトレードオフ

【未解決】 全ノードが同一周期（5秒固定）で送信する場合、送信タイミングが同期しバースト（thundering herd）が発生するリスクがある。周期にランダムジッタ（例: 5秒±1秒）を導入する設計が必要。

# 5. 制御メッセージプロトコル（暫定）

【未解決】 ワイヤーフォーマット未確定（先頭1バイトのみメッセージタイプとして規定、以降のフィールド境界・エンディアン・バージョン番号は未設計）。

【未解決】 受信データの境界チェック（最小長検証）が未実装。破損/不正パケットによる範囲外アクセスのリスクがある。

【未解決】 HandleControlMessage から RouteControlMessage への送信元エンドポイント伝播が未実装。

# 6. セキュリティ

## 6.1. メディアチャネル

AES-256-GCMによる暗号化・認証を行う。3.4節に記載のNonce再利用の脆弱性が最優先の対応事項である。

【未解決】 暗号化時のAAD（追加認証データ）が未使用。送信元/宛先やセッションIDをAADに含めることで、暗号文の付け替え耐性が向上する。

## 6.2. 制御チャネル

【未解決】 制御チャネル（ADVERTISE/HEARTBEAT）は現行無暗号・無認証。トポロジー情報は攻撃者にとって偵察価値が高く、詐称によるルーティング汚染のリスクがある。方針未確定（候補：軽量認証のみ付与／メディアと同一のAES-GCMを適用／現状維持し脅威モデルを明文化）。

# 7. 依存関係

# 8. 未解決事項 一覧（サマリ）

重大度が高い順に記載する。

【重大】GCM Nonce再利用の脆弱性への対策方式の決定（3.4節）

【重大】Send()呼び出し時のuse-after-free修正（3.4節）

制御チャネルの暗号化要否（6.2節）

QuicNgTcp2Transport の扱い（廃棄 or Push型への書き直し）（2章）

TopologyManagerのノード識別モデル（IP主キー→node_id主キーへの変更要否）（3.6節）

親ノードタイムアウト後の即時再選定ロジック（3.6節）

neighbor_nodes_のプルーニング実装（3.6節）

グループ分割アルゴリズムの設計（4.3節）

プローブ送信タイミングのジッタ導入（4.4節）

制御メッセージのワイヤーフォーマット確定（5章）

受信データの境界チェック実装（5章）

鍵のメモリゼロ化（3.3節）

暗号化AADの導入要否（6.1節）

ComputeNodeScoreの重み係数の妥当性検証（3.6節）

neighbor_nodes_/best_scores_の排他制御（3.6節）
