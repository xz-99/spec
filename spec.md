# 系统篇
## filecoin节点
### 节点类型
#### 节点接口
```
import repo "github.com/filecoin-project/specs/systems/filecoin_nodes/repository"
import filestore "github.com/filecoin-project/specs/systems/filecoin_files/file"
import clock "github.com/filecoin-project/specs/systems/filecoin_nodes/clock"
import libp2p "github.com/filecoin-project/specs/libraries/libp2p"
import message_pool "github.com/filecoin-project/specs/systems/filecoin_blockchain/message_pool"
import ipld "github.com/filecoin-project/specs/libraries/ipld"
import key_store "github.com/filecoin-project/specs/systems/filecoin_nodes/key_store"

type FilecoinNode struct {
    Node         libp2p.Node

    Repository   repo.Repository
    FileStore    filestore.FileStore
    Clock        clock.UTCClock
    LocalGraph   ipld.GraphStore
    KeyStore     key_store.KeyStore
    MessagePool  message_pool.MessagePoolSubsystem
}
```
#### 链验证器节点
```
type ChainVerifierNode interface {

  FilecoinNode

  systems.Blockchain
}
```
#### 客户端节点
```
type ClientNode struct {
  FilecoinNode

  systems.Blockchain
  markets.StorageMarketClient
  markets.RetrievalMarketClient
  markets.MarketOrderBook
  markets.DataTransfers
}
```
#### 存储旷工节点
```
type StorageMinerNode interface {
  FilecoinNode

  systems.Blockchain
  systems.Mining
  markets.StorageMarketProvider
  markets.MarketOrderBook
  markets.DataTransfers
}
```
#### 检索旷工节点
```
type RetrievalMinerNode interface {
  FilecoinNode

  blockchain.Blockchain
  markets.RetrievalMarketProvider
  markets.MarketOrderBook
  markets.DataTransfers
}
```
#### 中继节点
```
type RelayerNode interface {
  FilecoinNode

  blockchain.MessagePool
  markets.MarketOrderBook
}
```
### 存储库-链式数据和系统的本地存储
Filecoin节点存储库只是一个抽象，表示任何功能性Filecoin节点需要在本地存储以便正确运行的数据。

该存储库可供节点的系统和子系统访问，并充当与节点`FileStore`（例如）相对应的本地存储。

它存储节点的密钥，有状态对象的IPLD数据结构和节点配置。
```
import ipld "github.com/filecoin-project/specs/libraries/ipld"
import key_store "github.com/filecoin-project/specs/systems/filecoin_nodes/repository/key_store"
import config "github.com/filecoin-project/specs/systems/filecoin_nodes/repository/config"

type Repository struct {
    Config      config.Config
    KeyStore    key_store.KeyStore
    ChainStore  ipld.GraphStore
    StateStore  ipld.GraphStore
}
```
#### Config-ConfigurationValues的本地存储
Filecoin节点配置
```
type ConfigKey string
type ConfigVal Bytes

type Config struct {
    Get(k ConfigKey) union {c ConfigVal, e error}
    Put(k ConfigKey, v ConfigVal) error

    Subconfig(k ConfigKey) Config
}
```
#### 密钥库
这`Key Store`是任何完整的FIlecoin节点中的基本抽象，用于存储与给定旷工的地址和不同的工作人员关联的密钥对（旷工应该选择运行多个工作程序）。

节点安全性在很大程度上取决于保持这些密钥的安全性。为此，我们建议将密钥与任何给定子系统分开，并使用单独的密钥存储来按子系统的要求对请求你进行签名，并保留那些不用作冷库中挖掘的一部分的密钥。
```
import filcrypto "github.com/filecoin-project/specs/algorithms/crypto"
import address "github.com/filecoin-project/specs/systems/filecoin_vm/actor/address"

type KeyStore struct {
    MinerAddress  address.Address
    OwnerKey      filcrypto.VRFKeyPair
    WorkerKey     filcrypto.VRFKeyPair
}
```
FIlecoin存储旷工依赖于三个主要组成部分：调用储能共识子系统后，**旷工地址**唯一分配给给定的存储旷工角色`registerMiner()`。它是给定存储旷工的唯一标识符，其电源和其他密钥将与之关联。**所有者密钥对**由旷工在注册之前提供，并且其公钥与旷工地址相关。集体奖励和其他付款将支付给ownerAddress。**工人密钥对**可以由旷工选择和更改，其公钥与旷工地址相关。它用于签署交易，签名等。

虽然旷工地址是唯一的，但多个存储旷工参与者可以共享所有者公钥，也可以共享一个工人公钥。
#### IpldStore-散列链接数据的本地存储
Filecoin数据结构以IPLD格式存储，类似于json的数据格式，用于存储，检索和遍历散列链接的数据DAG。

Filecoin网络主要依赖于两个不同的IPLD GraphStore：

一种`ChainStore`存储区块链的数据，包括区块头，相关信息等。  
一种`StateStore`存储来自给定`statetree`区块链的有效载荷状态，或者是由[FIlecoin VM] (https://filecoin-project.github.io/specs/#systems__filecoin_vm)将给定链中所有区块消息的结果应用于创世转态的一种。

`chainStore`是通过从他们的同辈节点中的所述引导阶段下载[ChainSync-同步Blockchain] (https://filecoin-project.github.io/specs/#systems__filecoin_blockchain__chainsync)并且此后由所述节点存储。每次接收到新的块时，或者节点同步到新的最佳链时，都会对其进行更新。  
`StateStore`是通过在给定的所有块消息的执行计算`ChainStore`,然后由节点存储。它与每一个新的输入块的由处理更新[VM解释器-消息调用（外VM）] (https://filecoin-project.github.io/specs/#systems__filecoin_vm__interpreter)，并通过在该块的顶上它产生新块相应参与块报头的`ParentState`字段。  
什么是IPLD：  
哈希链接数据  
来自IPFS  

为什么和Filecoin相关：  
所有网络数据结构均经过IPLD确定  
所有本地数据结构都可以是IPLD  

什么是ipldStore：  
本地存储

一个或多个ipldstore：  
临时缓存  
中间计算状态

垃圾收集
### 网络接口
Filecoin节点使用Libp2p协议进行对等发现，对等路由和消息多播等。Libp2p是对等网络堆栈通用的一组模块化协议。节点彼此之间打开连接，并在同一连接上安装不同的协议或流。在最初的握手中，节点交换他们各自支持的协议，所有与Filecoin相关的/fil/...协议都将安装在协议标识符下。  
  
这是Filecoin使用的Libp2p协议的列表。  
Graphsync:  用于传输区块链和用户数据。  
[关于Graphsync] (https://github.com/ipld/specs/blob/master/block-layer/graphsync/graphsync.md "Graphsync")  
Gossipsub：区块头和消息通过Gossip PubSub协议广播，其中节点可以订阅区块链数据的主题并接收这些主题中的消息。当接收到与主题相关的消息时,节点将处理该消息并将其转发给也订阅同一主题的同级。  
[关于Gossipsub]  (https://github.com/libp2p/specs/tree/master/pubsub/gossipsub "Gossipsub")  
Kademlia DHT：是一个分布式哈希表，在特定节点的最大查找数上具有对数范围。Kad DHT主要用于Filecoin协议中的对等路由以及对等发现。  
[参考实施]  (https://github.com/libp2p/go-libp2p-kad-dht "Kademlia")  
Bootstrap List：是新节点加入网络后尝试连接的节点列表。引导节点列表及其地址有用户定义。  
Peer Exchange：是一种发现协议，使对等方可以针对所需对等方针对其现有对等方创建并发出查询  
[关于Peer Exchange]  (https://github.com/libp2p/specs/issues/222 "Peer Exchange")  
DNSDiscovery：(截至文档完成，正在设计与完善中) 
HTTPDiscovery：(截至文档完成，正在设计与完善中)  
Hello：处理与Filecoin节点的新连接。这是环境协议（例如KademliaDHT）发现过程中的重要组成部分。  
### 时钟
```
type UnixTime int64  // unix timestamp

// UTCClock is a normal, system clock reporting UTC time.
// It should be kept in sync, with drift less than 1 second.
type UTCClock struct {
    NowUTCUnix() UnixTime
}

// ChainEpoch represents a round of a blockchain protocol.
type ChainEpoch UVarint

// ChainEpochClock is a clock that represents epochs of the protocol.
type ChainEpochClock struct {
    // GenesisTime is the time of the first block. EpochClock counts
    // up from there.
    GenesisTime              UnixTime

    EpochAtTime(t UnixTime)  ChainEpoch
}
```
```
package clock

import "time"

// UTCSyncPeriod notes how often to sync the UTC clock with an authoritative
// source, such as NTP, or a very precise hardware clock.
var UTCSyncPeriod = time.Hour

// EpochDuration is a constant that represents the duration in seconds
// of a blockchain epoch.
var EpochDuration = UnixTime(15)

func (_ *UTCClock_I) NowUTCUnix() UnixTime {
	return UnixTime(time.Now().Unix())
}

// EpochAtTime returns the ChainEpoch corresponding to time `t`.
// It first subtracts GenesisTime, then divides by EpochDuration
// and returns the resulting number of epochs.
func (c *ChainEpochClock_I) EpochAtTime(t UnixTime) ChainEpoch {
	difference := t - c.GenesisTime()
	epochs := difference / EpochDuration
	return ChainEpoch(epochs)
}
```
Filecoin假定系统参与者之间的时钟同步较弱。也就是说，系统依赖于参与者可以访问全局同步时钟（可承受一定限度的漂移）。  
Filecoin依靠此系统时钟来确保共识。具体来说，时钟是支持验证规则所必需的，该验证规则可防止块生产者使用未来的时间戳来挖掘块，并且阻止领导者选举的发生超出协议允许的频率。
#### 时钟用途
使用FIlecoin系统时钟：  
通过同步节点来验证传入块是否在给定时间戳的适当纪元内被挖出（请参见 [块验证]  (https://filecoin-project.github.io/specs/#systems__filecoin_blockchain__block__block_validation) ）。这是可能的，因为系统时钟始终映射到唯一的纪元号，该纪元完全由创世块中的开始时间确定。  
通过同步节点以放置来自未来纪元的数据块  
通过挖掘节点以允许参与者在下一轮尝试领导者选举（如果当前轮中没有人产生障碍）的情况下保持协议的活跃性（请参阅 [储能共识] (https://filecoin-project.github.io/specs/#systems__filecoin_blockchain__storage_power_consensus___index)）。  

为了允许旷工执行上述操作，系统时钟必须：  
1.相对于其他节点具有足够低的时钟漂移（sub 1s），以使不会在其他节点的迫切情况下的被认为是未来纪元的纪元中挖掘区块（这些块直到根据 [验证规则] (https://filecoin-project.github.io/specs/#systems__filecoin_blockchain__struct__block___index)的适当纪元/时间才被 [验证] (https://filecoin-project.github.io/specs/#systems__filecoin_blockchain__struct__block___index)）。  
2.设置节点初始化的时期数等于` epoch = Floor[(current_time - genesis_time) / epoch_time]`  
预计其他子系统将从时钟子系统注册到NewRound () 事件。
#### 时钟要求
用作Filecoin协议一部分的时钟应保持同步，且漂移应小于1秒，以便进行适当验证。  
可以预期，计算机时钟晶体的漂移速率约为 [1ppm] (https://www.hindawi.com/journals/jcnc/2008/583162/)（即每秒1微秒或每周0.6秒），因此，为了满足上述要求：  
客户端应` pool.ntp.org`每小时查询NTP服务器（建议）以调整时钟偏斜。  
我们建议以下之一：  
`pool.ntp.org`（可以迎合 [特定区域] (https://www.ntppool.org/zone)）  
` time.cloudflare.com:1234`（有关 [Cloudflare时间服务的] (https://www.cloudflare.com/time/)更多信息）  
`time.google.com`(有关 [Google Public NTP的] (https://developers.google.com/time)更多信息)  
`ntp-b.nist.gov`( [NIST] (https://tf.nist.gov/tf-cgi/servers.cgi)服务器需要注册)  

采矿业务有强烈的动机来防止其时钟向前偏移一个以上的时间，以防止其提交的区块被拒绝。同样地，他们有动机来防止其时钟向后漂移超过一个纪元，从而避免将自己与网络中的同步节点分开。
#### 未来的工作
如果以上任一指标显示随时间推移出现明显的网络倾斜，则Filecoin的未来版本可能会定期包含潜在的时间戳/历元校正周期。  

当从异常链暂停中断恢复时（例如，所有实现都对给定的区块感到恐慌），网络可能会选择按中断的“死区“规则来禁止在中断时期内编写区块，以防止与未挖掘时期相关的攻击媒介链重启。  

Filecoin协议的未来版本可能会使用可验证延迟功能（VDF）来强制执行阻止时间并满足此领导者选举要求；我们选择明确假设时钟同步，知道硬件VDF安全性得到更广泛的证明为止。
## 文件和数据
Filecoin的主要目的是根据存储客户的文件和数据。本节详细介绍与处理文件，分块，编码，图形表示`Pieces`,存储抽象等相关的数据结构和工具。
### 文件
```
// Path is an opaque locator for a file (e.g. in a unix-style filesystem).
type Path string

// File is a variable length data container.
// The File interface is modeled after a unix-style file, but abstracts the
// underlying storage system.
type File interface {
    Path()   Path
    Size()   int
    Close()  error

    // Read reads from File into buf, starting at offset, and for size bytes.
    Read(offset int, size int, buf Bytes) struct {size int, e error}

    // Write writes from buf into File, starting at offset, and for size bytes.
    Write(offset int, size int, buf Bytes) struct {size int, e error}
}
```
#### FileStore-文件的本地存储
`FileStore`是用来指任何底层系统或设备，其将Filecoin数据存储到一个抽象，它基于Unix文件系统语义，并包含的概念`Paths`。在这里使用这种抽象是为了确保Filecoin的实现使最终用户可以轻松地使用适合他们需求的基础替换底层存储系统。最简单的版本`FileStore`只是主机操作系统的文件系统。
```
// FileStore is an object that can store and retrieve files by path.
type FileStore struct {
    Open(p Path)           union {f File, e error}
    Create(p Path)         union {f File, e error}
    Store(p Path, f File)  error
    Delete(p Path)         error

    // maybe add:
    // Copy(SrcPath, DstPath)
}
```
#### 变化的用户需求
Filecoin用户的需求差异很大，许多用户（尤其是旷工）将在Filecoin的下方和周围实施复杂的存储架构。`FileStore`这里的抽象是为了使这些变化的需求易于满足。FIlecoin协议中的所有文件和扇区本地数据缓存都是通过此`FileStore`接口定义的，这使得实现易于交换，并且使最终用户可以轻松选择所选择的系统。
#### 实施实例
该`FileStore`接口可以由多种后备数据存储系统来实现。例如：  
1.主机操作系统文件系统  
2.任何Unix/Posix文件系统  
3.RAID支持的文件系统  
4.联网的分布式文件系统（NFS，HDFS等）  
5.IPFS  
6.资料库  
7.NAS系统  
8.原始串行或块设备  
9.原始硬盘驱动器（hdd扇区等）  

实现对主机OS文件系统的支持，实现对其他存储系统的支持。
### Piece文件的一部分
片段是代表文件整体或一部分的对象，供交易中的客户和矿工使用。 客户雇用矿工来存储碎片。片段数据结构设计用于证明存储任意IPLD图和客户端数据。该图显示了一个Piece的详细组成及其证明树，包括完整的和带宽优化的块数据结构。
![Piece,证明树和Piece数据结构] (https://filecoin-project.github.io/specs/docs/systems/filecoin_files/piece/diagrams/pieces.png)      

```
import ipld "github.com/filecoin-project/specs/libraries/ipld"

// PieceCID is the main reference to pieces in Filecoin. It is the CID
// of the Piece.
type PieceCID ipld.CID

type NumBytes UVarint  // TODO: move into util

// PieceSize is the size of a piece, in bytes
type PieceSize struct {
    PayloadSize   NumBytes
    OverheadSize  NumBytes

    Total()       NumBytes
}

// PieceInfo is an object that describes details about a piece, and allows
// decoupling storage of this information from the piece itself.
type PieceInfo struct {
    ID    PieceID
    Size  PieceSize
    // TODO: store which algorithms were used to construct this piece.
}

// Piece represents the basic unit of tradeable data in Filecoin. Clients
// break files and data up into Pieces, maybe apply some transformations,
// and then hire Miners to store the Pieces.
//
// The kinds of transformations that may ocurr include erasure coding,
// encryption, and more.
//
// Note: pieces are well formed.
type Piece struct {
    Info       PieceInfo

    // tree is the internal representation of Piece. It is a tree
    // formed according to a sequence of algorithms, which make the
    // piece able to be verified.
    tree       PieceTree

    // Payload is the user's data.
    Payload()  Bytes

    // Data returns the serialized representation of the Piece.
    // It includes the payload data, and intermediate tree objects,
    // formed according to relevant storage algorithms.
    Data()     Bytes
}

// // LocalPieceRef is an object used to refer to pieces in local storage.
// // This is used by subsystems to store and locate pieces.
// type LocalPieceRef struct {
//   ID   PieceID
//   Path file.Path
// }

// PieceTree is a data structure used to form pieces. The algorithms involved
// in the storage proofs determine the shape of PieceTree and how it must be
// constructed.
//
// Usually, a node in PieceTree will include either Children or Data, but not
// both.
//
// TODO: move this into filproofs -- use a tree from there, as that's where
// the algorightms are defined. Or keep this as an interface, met by others.
type PieceTree struct {
    Children  [PieceTree]
    Data      Bytes
}
```
#### PieceStore-存储和索引件
A `PieceStore`是可以用来存储和从本地存储中检索片段的对象。在`PieceStore`另外保持件的索引。

```
import ipld "github.com/filecoin-project/specs/libraries/ipld"

type PieceID UVarint

// PieceStore is an object that stores pieces into some local storage.
// it is internally backed by an IpldStore.
type PieceStore struct {
    Store              ipld.GraphStore
    Index              {PieceID: Piece}

    Get(i PieceID)     struct {p Piece, e error}
    Put(p Piece)       error
    Delete(i PieceID)  error
}
```
### Filecoin中的数据传输
数据传输是一种用于`Piece`在进行交易时跨网络传输全部或部分网络的系统。
#### 模组
此图显示了数据传输及其模块如何与存储检索市场相匹配。特别要注意，如何将来自市场的数据传输请求验证器插入“数据传输“模块，但其代码属于市场系统。
![数据传输-推送流程] (https://filecoin-project.github.io/specs/docs/systems/filecoin_files/data_transfer/data-transfer-modules.png)
#### 术语
1.**推送请求**：向对方发送数据的请求  
2.**拉取请求**：请求对方发送数据的请求  
3.**请求者**：发起数据传输请求的一方（无论推还是拉）  
4.**响应者**：接收数据传输请求的一方  
5.**数据传输凭证**：围绕存储或检索数据的包装，可以识别和验证向另一方的传输请求  
6.**请求验证器**：仅当响应者可以验证请求是否直接与现有存储协议或检索协议绑定时，数据传输模块才启动传输。验证不由数据传输模块本身执行。而是由请求验证器检查数据传输凭证以确定是否响应请求。  
7.**调度程序**：协商和确认请求后，实际的传输将由双方的调度程序管理。调度程序是数据传输模块的一部分，但与协商过程隔离。它可以访问基础可验证的传输协议，并使用它来发送数据和跟踪进度。  
8.**Subscriber**：一个外部组件，通过订阅数据传输事件（例如进度或完成）来监视数据传输的进度。  
9.**GraphSync**：调度程序使用的默认基础传输协议。完整的graphsync规范可以在[https://github.com/ipld/specs/blob/master/block-layer/graphsync/graphsync.md中] (https://github.com/ipld/specs/blob/master/block-layer/graphsync/graphsync.md)找到
#### 请求阶段
任何数据传输都有两个基本阶段：

1.协商-请求者和响应者通过使用数据传输凭证进行验证来同意传输  
2.传输-双方协商并达成协议后，数据实际上已传输。用于进行传输的默认协议是Graphsync

请注意，“协商”和“转移”阶段可以发生在单独的往返行程中，也可能在相同的往返行程中，其中请求方通过发送请求隐式同意，而响应方可以同意并立即发送或接收数据。
#### 流程示例
##### 推流
数据传输-推送流程图：  
![数据传输-推送流程](https://filecoin-project.github.io/specs/docs/systems/filecoin_files/data_transfer/push-flow.mmd.svg)

1.当请求者想要将数据发送给另一方时，它会发起“推”传输。  
2.请求者的数据传输模块将把推送请求与数据传输凭证一起发送给响应者。还将数据传输放入调度程序队列中，这意味着它期望响应者在请求被验证后就开始传输  
3.响应方的数据传输模块通过验证方验证数据传输请求，该验证方作为响应方提供的依赖项  
4.响应者的数据传输模块安排传输  
5.响应者对数据进行GraphSync请求  
6.请求者收到graphsync请求，验证它在调度程序中，然后开始发送数据  
7.响应者接收数据并可以显示进度指示  
8.响应者完成接收数据，并通知所有侦听器  

推送流程是存储交易的理想选择，其中客户一旦确认交易已签署并在链上就启动推送
##### 拉流
数据传输-拉流流程图：
![数据传输-拉流流程] (https://filecoin-project.github.io/specs/docs/systems/filecoin_files/data_transfer/pull-flow.mmd.svg)

1.当请求者想要从另一方接收数据时，它会发起拉式传输  
2.请求者的数据传输模块将向请求者发送拉取请求以及数据传输凭证。  
3.响应者的数据传输模块通过响应者作为依赖提供的PullValidator验证数据传输请求  
4.响应者的数据传输模块计划传输（这意味着它期望请求者发起实际的传输）  
5.响应者的数据传输模块向请求者发送响应，说它已经接受了传输并正在等待请求者启动传输  
6.请求者安排数据传输  
7.请求者对数据进行GraphSync请求  
8.响应者接收到graphsync请求，验证它在调度程序中，然后开始发送数据  
9.请求者接收数据并可以产生进度指示  
10.请求者完成接收数据，并通知所有侦听器  

拉动流程是检索交易的理想选择，在该交易中，客户在达成交易时会发起拉动。
##### 交流发电机拉流-单程往返
数据传输-单程往返拉动流程
![数据传输-单程往返拉动流程] (https://filecoin-project.github.io/specs/docs/systems/filecoin_files/data_transfer/alternate-pull-flow.mmd.svg)

1.当请求者想要从另一方接收数据时，它会发起拉式传输。  
2.请求者的DTM安排数据传输  
3.请求者通过数据传输请求向响应者发出Graphsync请求  
4.响应者接收到graphsync请求，并将数据传输请求转发到数据传输模块  
5.请求者的数据传输模块将向请求者发送拉取请求以及数据传输凭证。  
6.响应者的数据传输模块通过响应者作为依赖提供的PullValidator验证数据传输请求  
7.响应者的数据传输模块安排传输  
8.响应者发送图同步响应以及打包的数据传输接受响应  
9.请求者接收数据并可以产生进度指示  
10.请求者完成接收数据，并通知所有侦听器

#### 协议
可以通过Libp2p协议类型的[数据传输协议] (https://filecoin-project.github.io/specs/#listings__libp2p_protocols__data_transfer_protocol)在网络上[协商传输] (https://filecoin-project.github.io/specs/#listings__libp2p_protocols__data_transfer_protocol)  

拉取请求需要响应。在知道请求已被接收之前，请求者不会启动传输。  

响应者也应该发送对推送请求的响应，以便请求者可以释放资源（如果未接受）。但是，如果响应者接受了请求，他们可以立即启动传输  

使用数据传输协议作为独立的libp2p通讯机制并不是硬性要求-只要双方都实现了可以与对方通信的数据传输子系统，任何传输机制（包括离线机制）都是可以接受的。
#### 数据结构
```
import ipld "github.com/filecoin-project/specs/libraries/ipld"
import libp2p "github.com/filecoin-project/specs/libraries/libp2p"

import piece "github.com/filecoin-project/specs/systems/filecoin_files/piece"

type StorageDeal struct {}
type RetrievalDeal struct {}

// A DataTransferVoucher is used to validate
// a data transfer request against the underlying storage or retrieval deal
// that precipitated it
type DataTransferVoucher union {
    StorageDealVoucher
    RetrievalDealVoucher
}

type StorageDealVoucher struct {
    deal StorageDeal
}

type RetrievalDealVoucher struct {
    deal RetrievalDeal
}

type Ongoing struct {}
type Paused struct {}
type Completed struct {}
type Failed struct {}
type ChannelNotFoundError struct {}

type DataTransferStatus union {
    Ongoing
    Paused
    Completed
    Failed
    ChannelNotFoundError
}

type TransferID UInt

type ChannelID struct {
    to libp2p.PeerID
    id TransferID
}

// All immutable data for a channel
type DataTransferChannel struct {
    // an identifier for this channel shared by request and responder, set by requestor through protocol
    transferID  TransferID
    // base CID for the piece being transferred
    PieceRef    ipld.CID
    // portion of Piece to return, specified by an IPLD selector
    Selector    ipld.Selector
    // used to verify this channel
    voucher     DataTransferVoucher
    // the party that is sending the data (not who initiated the request)
    sender      libp2p.PeerID
    // the party that is receiving the data (not who initiated the request)
    recipient   libp2p.PeerID
    // expected amount of data to be transferred
    totalSize   UVarint
}

// DataTransferState is immutable channel data plus mutable state
type DataTransferState struct @(mutable) {
    DataTransferChannel
    // total bytes sent from this node (0 if receiver)
    sent                 UVarint
    // total bytes received by this node (0 if sender)
    received             UVarint
}

type Open struct {
    Initiator libp2p.PeerID
}

type SendData struct {
    BytesToSend UInt
}

type Progress struct {
    BytesSent UInt
}

type Pause struct {
    Initiator libp2p.PeerID
}

type Error struct {
    ErrorMsg string
}

type Complete struct {}

type DataTransferEvent union {
    Open
    SendData
    Progress
    Pause
    Error
    Complete
}

type DataTransferSubscriber struct {
    OnEvent(event DataTransferEvent, channelState DataTransferState)
}

// RequestValidator is an interface implemented by the client of the data transfer module to validate requests
type RequestValidator struct {
    ValidatePush(
        sender    libp2p.PeerID
        voucher   DataTransferVoucher
        PieceRef  ipld.CID
        Selector  ipld.Selector
    )
    ValidatePull(
        receiver  libp2p.PeerID
        voucher   DataTransferVoucher
        PieceRef  ipld.CID
        Selector  ipld.Selector
    )
    ValidateIntermediate(
        otherPeer  libp2p.PeerID
        voucher    DataTransferVoucher
        PieceRef   ipld.CID
        Selector   ipld.Selector
    )
}

type DataTransferSubsystem struct @(mutable) {
    host              libp2p.Node
    dataTransfers     {ChannelID: DataTransferState}
    requestValidator  RequestValidator
    pieceStore        piece.PieceStore

    // open a data transfer that will send data to the recipient peer and
    // open a data transfer that will send data to the recipient peer and
    // transfer parts of the piece that match the selector
    OpenPushDataChannel(
        to        libp2p.PeerID
        voucher   DataTransferVoucher
        PieceRef  ipld.CID
        Selector  ipld.Selector
    ) ChannelID

    // open a data transfer that will request data from the sending peer and
    // transfer parts of the piece that match the selector
    OpenPullDataChannel(
        to        libp2p.PeerID
        voucher   DataTransferVoucher
        PieceRef  ipld.CID
        Selector  ipld.Selector
    ) ChannelID

    // close an open channel (effectively a cancel)
    CloseDataTransferChannel(x ChannelID)

    // get status of a transfer
    TransferChannelStatus(x ChannelID) DataTransferStatus

    // pause an ongoing channel
    PauseChannel(x ChannelID)

    // resume an ongoing channel
    ResumeChannel(x ChannelID)

    // send an additional voucher for an in progress request
    SendIntermediateVoucher(x ChannelID, voucher DataTransferVoucher)

    // get notified when certain types of events happen
    SubscribeToEvents(subscriber DataTransferSubscriber)

    // get all in progress transfers
    InProgressChannels() {ChannelID: DataTransferState}
}
```
## VM-虚拟机
```
import msg "github.com/filecoin-project/specs/systems/filecoin_vm/message"
import st "github.com/filecoin-project/specs/systems/filecoin_vm/state_tree"

// VM is the object that controls execution.
// It is a stateless, pure function. It uses no local storage.
//
// TODO: make it just a function: VMExec(...) ?
type VM struct {
    // Execute computes and returns outTree, a new StateTree which is the
    // application of msgs to inTree.
    //
    // *Important:* Execute is intended to be a pure function, with no side-effects.
    // however, storage of the new parts of the computed outTree may exist in
    // local storage.
    //
    // *TODO:* define whether this should take 0, 1, or 2 IpldStores:
    // - (): storage of IPLD datastructures is assumed implicit
    // - (store): get and put to same IpldStore
    // - (inStore, outStore): get from inStore, put new structures into outStore
    //
    // This decision impacts callers, and potentially impacts how we reason about
    // local storage, and intermediate storage. It is definitely the case that
    // implementations may want to operate on this differently, depending on
    // how their IpldStores work.
    Execute(inTree st.StateTree, msgs [msg.UnsignedMessage]) union {outTree st.StateTree, err error}
}
```
### VM Actor接口
```
// This contains actor things that are _outside_ of VM exection.
// The VM uses this to execute abi.

import abi "github.com/filecoin-project/specs/actors/abi"
import ipld "github.com/filecoin-project/specs/libraries/ipld"

// CallSeqNum is an invocation (Call) sequence (Seq) number (Num).
// This is a value used for securing against replay attacks:
// each AccountActor (user) invocation must have a unique CallSeqNum
// value. The sequenctiality of the numbers is used to make it
// easy to verify, and to order messages.
//
// Q&A
// - > Does it have to be sequential?
//   No, a random nonce could work against replay attacks, but
//   making it sequential makes it much easier to verify.
// - > Can it be used to order events?
//   Yes, a user may submit N separate messages with increasing
//   sequence number, causing them to execute in order.
//
type CallSeqNum UVarint

// Code is a serialized object that contains the code for an Actor.
// Until we accept external user-provided contracts, this is the
// serialized code for the actor in the Filecoin Specification.
type Code Bytes

// Actor is a base computation object in the Filecoin VM. Similar
// to Actors in the Actor Model (programming), or Objects in Object-
// Oriented Programming, or Ethereum Contracts in the EVM.
//
// ActorState represents the on-chain storage all actors keep.
type ActorState struct {
    // Identifies the code this actor executes.
    CodeID      abi.ActorCodeID
    // CID of the root of optional actor-specific sub-state.
    State       ActorSubstateCID
    // Balance of tokens held by this actor.
    Balance     abi.TokenAmount
    // Expected sequence number of the next message sent by this actor.
    // Initially zero, incremented when an account actor originates a top-level message.
    // Always zero for other abi.
    CallSeqNum
}

type ActorSystemStateCID ipld.CID
type ActorSubstateCID ipld.CID

// ActorState represents the on-chain storage actors keep. This type is a
// union of concrete types, for each of the Actors:
// - InitActor
// - CronActor
// - AccountActor
// - PaymentChannelActor
// - StoragePowerActor
// - StorageMinerActor
// - StroageMarketActor
//
// TODO: move this into a directory inside the VM that patches in all
// the actors from across the system. this will be where we declare/mount
// all actors in the VM.
// type ActorState union {
//     Init struct {
//         AddressMap  {addr.Address: ActorID}
//         NextID      ActorID
//     }
// }
```
```
package actor

import (
	abi "github.com/filecoin-project/specs/actors/abi"
	ipld "github.com/filecoin-project/specs/libraries/ipld"
	util "github.com/filecoin-project/specs/util"
)

var IMPL_FINISH = util.IMPL_FINISH
var IMPL_TODO = util.IMPL_TODO
var TODO = util.TODO

type Serialization = util.Serialization

const (
	MethodSend        = abi.MethodNum(0)
	MethodConstructor = abi.MethodNum(1)

	// TODO: remove this once canonical method numbers are finalized
	MethodPlaceholder = abi.MethodNum(1 << 30)
)

func (st *ActorState_I) CID() ipld.CID {
	panic("TODO")
}

func (x ActorSubstateCID) Ref() *ActorSubstateCID {
	return &x
}
```
#### 地址
```
// Address is defined here because this is where addresses start to make sense.
// Addresses refer to actors defined in the StateTree, so Addresses are defined
// on top of the StateTree.
//
// TODO: potentially move into a library, or its own directory.
type Address struct {
    NetworkID enum {
        Testnet
        Mainnet
    }

    Data union {
        ID                   ActorID
        PublicKey_Secp256k1  KeyHash  // TODO: reorder
        ActorExec            ActorExecHash
        PublicKey_BLS        KeyHash
    }

    VerifySyntax()   bool
    String()         string
    IsIDType()       bool  // Whether the address is an ID-address
    IsKeyType()      bool  // Whether the address is a public key address (SECP or BLS)
    Equals(Address)  bool
    Ref()            Address_Ptr

    // Returns the ID from an ID address (or error otherwise).
    GetID()          (ActorID, error)
    GetKey()         (KeyHash, error)
}

// ActorID is a sequential number assigned to actors in a Filecoin Chain.
// ActorIDs are assigned by the InitActor, when an Actor is introduced into
// the Runtime.
type ActorID Int

type KeyHash Bytes
type ActorExecHash Bytes
```
### 状态树
状态树是在Filecoin区块链上应用操作的输出。  

```
import abi "github.com/filecoin-project/specs/actors/abi"
import actor "github.com/filecoin-project/specs/systems/filecoin_vm/actor"
import addr "github.com/filecoin-project/specs/systems/filecoin_vm/actor/address"
import ipld "github.com/filecoin-project/specs/libraries/ipld"

// The on-chain state data structure is a map (HAMT) of addresses to actor states.
// Only ID addresses are expected as keys.
type StateTree struct {
    ActorStates  {addr.Address: actor.ActorState}  // HAMT

    // Returns the CID of the root node of the HAMT.
    RootCID()    ipld.CID

    // Looks up an actor state by address.
    GetActor(a addr.Address) (state actor.ActorState, ok bool)

    // Looks up an abi.ActorCodeID by address.
    GetActorCodeID_Assert(a addr.Address) abi.ActorCodeID
}
```
添加ConvenienceAPI状态以提供更加用户友好的视图。
### 宏观经济指标
指标是根据状态数计算的一组全球经济指标，以及用于基于用户状态/操作来计算策略输出的纯函数的集合。指数用于计算和实施系统的经济机制和政策。指数中没有持久性状态。索引也不会引入任何状态突变。请注意，索引应该存放在哪里是设计决策。一旦确定了所有经济机制，就有可能将指数分为多个文件或将索引放置在不同的参与者。暂时，指数是系统需要了解的所有潜在宏观经济指标的保留文件。

```
import abi "github.com/filecoin-project/specs/actors/abi"
import actor_util "github.com/filecoin-project/specs/actors/util"
import piece "github.com/filecoin-project/specs/systems/filecoin_files/piece"
import sector "github.com/filecoin-project/specs/systems/filecoin_mining/sector"
import deal "github.com/filecoin-project/specs/systems/filecoin_markets/storage_market/storage_deal"

// Data in Indices are populated at instantiation with data from the state tree
// Indices itself has no state tree or access to the runtime
// it is a passive data structure that allows for convenience access to network indices
// and pure functions in implementing economic policies given states
type Indices struct {
    // these fields are computed from StateTree upon construction
    // they are treated as globally available states
    Epoch                       abi.ChainEpoch
    NetworkKPI                  BigInt
    TotalNetworkSectorWeight    abi.SectorWeight
    TotalPledgeCollateral       abi.TokenAmount
    TotalNetworkEffectivePower  abi.StoragePower  // power above minimum miner size
    TotalNetworkPower           abi.StoragePower  // total network power irrespective of meeting minimum miner size

    TotalMinedFIL               abi.TokenAmount
    TotalUnminedFIL             abi.TokenAmount
    TotalBurnedFIL              abi.TokenAmount
    LastEpochReward             abi.TokenAmount

    // these methods produce policy output based on user state/action
    StorageDeal_ProviderInitTimedOutSlashAmount(deal deal.OnChainDeal) abi.TokenAmount

    StorageDeal_DurationBounds(
        pieceSize   piece.PieceSize
        startEpoch  abi.ChainEpoch
    ) (minDuration abi.ChainEpoch, maxDuration abi.ChainEpoch)

    StorageDeal_StoragePricePerEpochBounds(
        pieceSize   piece.PieceSize
        startEpoch  abi.ChainEpoch
        endEpoch    abi.ChainEpoch
    ) (minPrice abi.TokenAmount, maxPrice abi.TokenAmount)

    StorageDeal_ProviderCollateralBounds(
        pieceSize   piece.PieceSize
        startEpoch  abi.ChainEpoch
        endEpoch    abi.ChainEpoch
    ) (
        minProviderCollateral  abi.TokenAmount
        maxProviderCollateral  abi.TokenAmount
    )

    StorageDeal_ClientCollateralBounds(
        pieceSize   piece.PieceSize
        startEpoch  abi.ChainEpoch
        endEpoch    abi.ChainEpoch
    ) (
        minClientCollateral  abi.TokenAmount
        maxClientCollateral  abi.TokenAmount
    )

    SectorWeight(
        sectorSize  sector.SectorSize
        startEpoch  abi.ChainEpoch
        endEpoch    abi.ChainEpoch
        dealWeight  deal.DealWeight
    ) abi.SectorWeight

    PledgeCollateralReq(
        minerNominalPower abi.StoragePower
    ) abi.TokenAmount

    SectorWeightProportion(
        minerActiveSectorWeight abi.SectorWeight
    ) BigInt

    PledgeCollateralProportion(
        minerPledgeCollateral abi.TokenAmount
    ) BigInt

    StoragePower(
        minerActiveSectorWeight    abi.SectorWeight
        minerInactiveSectorWeight  abi.SectorWeight
        minerPledgeCollateral      abi.TokenAmount
    ) abi.StoragePower

    StoragePowerProportion(
        minerStoragePower abi.StoragePower
    ) BigInt

    CurrEpochBlockReward() abi.TokenAmount

    GetCurrBlockRewardForMiner(
        minerStoragePower      abi.StoragePower
        minerPledgeCollateral  abi.TokenAmount
    ) abi.TokenAmount

    StorageMining_PreCommitDeposit(
        sectorSize       sector.SectorSize
        expirationEpoch  abi.ChainEpoch
    ) abi.TokenAmount

    StorageMining_TemporaryFaultFee(
        storageWeightDescs  [actor_util.SectorStorageWeightDesc]
        duration            abi.ChainEpoch
    ) abi.TokenAmount

    StoragePower_PledgeSlashForSectorTermination(
        storageWeightDesc  actor_util.SectorStorageWeightDesc
        terminationType    actor_util.SectorTerminationType
    ) abi.TokenAmount

    StoragePower_PledgeSlashForSurprisePoStFailure(
        minerClaimedPower       abi.StoragePower
        numConsecutiveFailures  int
    ) abi.TokenAmount

    StoragePower_ConsensusMinMinerPower() abi.StoragePower

    NetworkTransactionFee(
        toActorCodeID  abi.ActorCodeID
        methodNum      abi.MethodNum
    ) abi.TokenAmount
}
```
```
package indices

import (
	abi "github.com/filecoin-project/specs/actors/abi"
	actor_util "github.com/filecoin-project/specs/actors/util"
	piece "github.com/filecoin-project/specs/systems/filecoin_files/piece"
	deal "github.com/filecoin-project/specs/systems/filecoin_markets/storage_market/storage_deal"
	sector "github.com/filecoin-project/specs/systems/filecoin_mining/sector"
	st "github.com/filecoin-project/specs/systems/filecoin_vm/state_tree"
	util "github.com/filecoin-project/specs/util"
)

var PARAM_FINISH = util.PARAM_FINISH

func Indices_FromStateTree(tree st.StateTree) Indices {
	PARAM_FINISH()
	panic("")
}

func StorageDeal_ProviderInitTimedOutSlashAmount(deal deal.OnChainDeal) abi.TokenAmount {
	// placeholder
	PARAM_FINISH()
	return deal.Deal().Proposal().ProviderBalanceRequirement()
}

func (inds *Indices_I) StorageDeal_DurationBounds(
	pieceSize piece.PieceSize,
	startEpoch abi.ChainEpoch,
) (minDuration abi.ChainEpoch, maxDuration abi.ChainEpoch) {

	// placeholder
	PARAM_FINISH()
	minDuration = abi.ChainEpoch(0)
	maxDuration = abi.ChainEpoch(1 << 20)
	return
}

func (inds *Indices_I) StorageDeal_StoragePricePerEpochBounds(
	pieceSize piece.PieceSize,
	startEpoch abi.ChainEpoch,
	endEpoch abi.ChainEpoch,
) (minPrice abi.TokenAmount, maxPrice abi.TokenAmount) {

	// placeholder
	PARAM_FINISH()
	panic("")
}

func (inds *Indices_I) StorageDeal_ProviderCollateralBounds(
	pieceSize piece.PieceSize,
	startEpoch abi.ChainEpoch,
	endEpoch abi.ChainEpoch,
) (minProviderCollateral abi.TokenAmount, maxProviderCollateral abi.TokenAmount) {

	// placeholder
	PARAM_FINISH()
	panic("")
}

func (inds *Indices_I) StorageDeal_ClientCollateralBounds(
	pieceSize piece.PieceSize,
	startEpoch abi.ChainEpoch,
	endEpoch abi.ChainEpoch,
) (minClientCollateral abi.TokenAmount, maxClientCollateral abi.TokenAmount) {

	// placeholder
	PARAM_FINISH()
	panic("")
}

func (inds *Indices_I) SectorWeight(
	sectorSize sector.SectorSize,
	startEpoch abi.ChainEpoch,
	endEpoch abi.ChainEpoch,
	dealWeight deal.DealWeight,
) abi.SectorWeight {
	// for every sector, given its size, start, end, and deals within the sector
	// assign sector power for the duration of its lifetime
	PARAM_FINISH()
	panic("")
}

func (inds *Indices_I) PledgeCollateralReq(minerNominalPower abi.StoragePower) abi.TokenAmount {
	PARAM_FINISH()
	panic("")
}

func (inds *Indices_I) SectorWeightProportion(minerActiveSectorWeight abi.SectorWeight) util.BigInt {
	// return proportion of SectorWeight for miner
	PARAM_FINISH()
	panic("")
}

func (inds *Indices_I) PledgeCollateralProportion(minerPledgeCollateral abi.TokenAmount) util.BigInt {
	// return proportion of Pledge Collateral for miner
	PARAM_FINISH()
	panic("")
}

func (inds *Indices_I) StoragePower(
	minerActiveSectorWeight abi.SectorWeight,
	minerInactiveSectorWeight abi.SectorWeight,
	minerPledgeCollateral abi.TokenAmount,
) abi.StoragePower {
	// return StoragePower based on inputs
	// StoragePower for miner = func(ActiveSectorWeight for miner, PledgeCollateral for miner, global indices)
	PARAM_FINISH()
	panic("")
}

func (inds *Indices_I) StoragePowerProportion(
	minerStoragePower abi.StoragePower,
) util.BigInt {
	PARAM_FINISH()
	panic("")
}

func (inds *Indices_I) CurrEpochBlockReward() abi.TokenAmount {
	// total block reward allocated for CurrEpoch
	// each expected winner get an equal share of this reward
	// computed as a function of NetworkKPI, LastEpochReward, TotalUnmminedFIL, etc
	PARAM_FINISH()
	panic("")
}

func (inds *Indices_I) GetCurrBlockRewardRewardForMiner(
	minerStoragePower abi.StoragePower,
	minerPledgeCollateral abi.TokenAmount,
	// TODO extend or eliminate
) abi.TokenAmount {
	PARAM_FINISH()
	panic("")
}

// TerminationFault
func (inds *Indices_I) StoragePower_PledgeSlashForSectorTermination(
	storageWeightDesc actor_util.SectorStorageWeightDesc,
	terminationType actor_util.SectorTerminationType,
) abi.TokenAmount {
	PARAM_FINISH()
	panic("")
}

// DetectedFault
func (inds *Indices_I) StoragePower_PledgeSlashForSurprisePoStFailure(
	minerClaimedPower abi.StoragePower,
	numConsecutiveFailures int,
) abi.TokenAmount {
	PARAM_FINISH()
	panic("")
}

func (inds *Indices_I) StorageMining_PreCommitDeposit(
	sectorSize sector.SectorSize,
	expirationEpoch abi.ChainEpoch,
) abi.TokenAmount {
	PARAM_FINISH()
	panic("")
}

func (inds *Indices_I) StorageMining_TemporaryFaultFee(
	storageWeightDescs []actor_util.SectorStorageWeightDesc,
	duration abi.ChainEpoch,
) abi.TokenAmount {
	PARAM_FINISH()
	panic("")
}

func (inds *Indices_I) NetworkTransactionFee(
	toActorCodeID abi.ActorCodeID,
	methodNum abi.MethodNum,
) abi.TokenAmount {
	PARAM_FINISH()
	panic("")
}

func ConsensusPowerForStorageWeight(
	storageWeightDesc actor_util.SectorStorageWeightDesc,
) abi.StoragePower {
	PARAM_FINISH()
	panic("")
}

func StoragePower_ConsensusMinMinerPower() abi.StoragePower {
	PARAM_FINISH()
	panic("")
}

func StorageMining_PoStNoChallengePeriod() abi.ChainEpoch {
	PARAM_FINISH()
	panic("")
}

func StorageMining_SurprisePoStProvingPeriod() abi.ChainEpoch {
	PARAM_FINISH()
	panic("")
}

func StoragePower_SurprisePoStMaxConsecutiveFailures() int {
	PARAM_FINISH()
	panic("")
}

func StorageMining_DeclaredFaultEffectiveDelay() abi.ChainEpoch {
	PARAM_FINISH()
	panic("")
}
```
## 地址
Filecoin地址是一个标识符，它引用处于Filecoin状态的参与者。所有参与者（旷工，存储市场参与者，账户参与者）都有地址。该地址编码有关参与者所属的网络，地址编码的特定类型，地址有效负载本身以及校验和的信息。这种格式的目标是提供一种既易于使用又可防止错误的可靠地址格式。  

```
// Address is defined here because this is where addresses start to make sense.
// Addresses refer to actors defined in the StateTree, so Addresses are defined
// on top of the StateTree.
//
// TODO: potentially move into a library, or its own directory.
type Address struct {
    NetworkID enum {
        Testnet
        Mainnet
    }

    Data union {
        ID                   ActorID
        PublicKey_Secp256k1  KeyHash  // TODO: reorder
        ActorExec            ActorExecHash
        PublicKey_BLS        KeyHash
    }

    VerifySyntax()   bool
    String()         string
    IsIDType()       bool  // Whether the address is an ID-address
    IsKeyType()      bool  // Whether the address is a public key address (SECP or BLS)
    Equals(Address)  bool
    Ref()            Address_Ptr

    // Returns the ID from an ID address (or error otherwise).
    GetID()          (ActorID, error)
    GetKey()         (KeyHash, error)
}

// ActorID is a sequential number assigned to actors in a Filecoin Chain.
// ActorIDs are assigned by the InitActor, when an Actor is introduced into
// the Runtime.
type ActorID Int

type KeyHash Bytes
type ActorExecHash Bytes
```
```
package address

import (
	"errors"

	util "github.com/filecoin-project/specs/util"
)

var Assert = util.Assert

type Int = util.Int

// Addresses for singleton system abi.
var (
	// Distinguished AccountActor that is the source of system implicit messages.
	SystemActorAddr        = Address_Make_ID(Address_NetworkID_Testnet, 0)
	InitActorAddr          = Address_Make_ID(Address_NetworkID_Testnet, 1)
	RewardActorAddr        = Address_Make_ID(Address_NetworkID_Testnet, 2)
	CronActorAddr          = Address_Make_ID(Address_NetworkID_Testnet, 3)
	StoragePowerActorAddr  = Address_Make_ID(Address_NetworkID_Testnet, 4)
	StorageMarketActorAddr = Address_Make_ID(Address_NetworkID_Testnet, 5)
	// Distinguished AccountActor that is the destination of all burnt funds.
	BurntFundsActorAddr = Address_Make_ID(Address_NetworkID_Testnet, 99)
)

const FirstNonSingletonActorId = 100

func (a *Address_I) VerifySyntax() bool {
	panic("TODO")
	// switch aType := addrType; aType {
	// case Address_Protocol.Secp256k1():
	// 	// 80 Bytes
	// 	return len(self)
	// case Address_Protocol.ID():
	// 	// ?
	// case Address_Protocol.Actor():
	// 	// Blake2b - 64 Bytes
	// case Address_Protocol.BLS():
	// 	// BLS-12_381 - 48 Byte PK
	// }
}

func (a *Address_I) Equals(Address) bool {
	panic("TODO")
}

func (a *Address_I) String() string {
	return string(Serialize_Address_Compact(a))
}

func Serialize_Address_Compact(Address) util.Serialization {
	// TODO: custom encoding as in
	// https://github.com/filecoin-project/lotus/blob/master/chain/address/address.go
	panic("TODO")
}

func Deserialize_Address_Compact(util.Serialization) (Address, error) {
	// TODO: custom encoding as in
	// https://github.com/filecoin-project/lotus/blob/master/chain/address/address.go
	panic("TODO")
}

func Deserialize_Address_Compact_Assert(x util.Serialization) Address {
	ret, err := Deserialize_Address_Compact(x)
	Assert(err == nil)
	return ret
}

func (a *Address_I) IsIDType() bool {
	panic("TODO")
}

func (a *Address_I) IsKeyType() bool {

	panic("TODO")
}

func (a *Address_I) GetID() (ActorID, error) {
	if !a.IsIDType() {
		return ActorID(0), errors.New("not an ID address")
	}
	return a.Data_.As_ID(), nil
}

func (a *Address_I) GetKey() (KeyHash, error) {
	if !a.IsKeyType() {
		return KeyHash(nil), errors.New("not a key address")
	}
	if a.Data_.Which() == Address_Data_Case_PublicKey_BLS {
		return a.Data_.As_PublicKey_BLS(), nil
	} else if a.Data_.Which() == Address_Data_Case_PublicKey_Secp256k1 {
		return a.Data_.As_PublicKey_Secp256k1(), nil
	} else {
		return KeyHash(nil), errors.New("not a recognized key type")
	}
}

func Address_Make_ID(net Address_NetworkID, x ActorID) Address {
	return &Address_I{
		NetworkID_: net,
		Data_:      Address_Data_Make_ID(x),
	}
}

func Address_Make_Key(net Address_NetworkID, x KeyHash) (Address, error) {
	var d Address_Data
	if util.IsBLS(x) {
		d = Address_Data_Make_PublicKey_BLS(x)
	} else if util.IsSECP(x) {
		d = Address_Data_Make_PublicKey_Secp256k1(x)
	} else {
		return nil, errors.New("Not a recognized key type")
	}
	return &Address_I{
		NetworkID_: net,
		Data_:      d,
	}, nil
}

func Address_Make_ActorExec(net Address_NetworkID, hash ActorExecHash) Address {
	return &Address_I{
		NetworkID_: net,
		Data_:      Address_Data_Make_ActorExec(hash),
	}
}

type Address_Ptr = *Address

func (a *Address_I) Ref() Address_Ptr {
	var ret Address = a
	return &ret
}
```
### 设计标准
1.**可识别的**：该地址必须易于识别为Filecoin地址。  
2.**可靠**：当地址可能在网络外传输时，地址必须提供一种错误检测机制。  
3.**可升级**：地址必须经过版本控制，以允许引入新的地址格式。  
4.**紧凑**：鉴于上述限制，地址必须尽可能短。
### 规格
有两种方式可以表示Filecoin地址。出现在链上的地址将始终被格式化为原始字节。地址也可以编码为字符串，此编码包括校验和网络前缀。编码为字符串的地址永远不会出现在链上，此格式用于在人与人之间共享。
#### 字节数
当以字节表示时，Filecoin地址包含一下内容：  

**协议指示符**字节标识此地址的类型和版本。  

用于根据协议唯一标识参与者的**有效负载**。  
#### 串
当编码为字符串时，Filecoin地址包含一下内容：  
**网络前缀**字符标识地址所属的网络。  
**协议指示符**字节标识此地址的类型和版本。  
**有效负荷**用于唯一根据所述协议标识演员。  
#### 网络前缀
编码为字符串时，**网络前缀**位于地址之前。网络前缀指示地址所属的网络。网络前缀可以用于FIlecoin或用于FIlecoin测试网。值得注意的是，网络前缀永远不会出现在链上，仅在地址编码为人类可读格式时使用。  
.  
.  
.  
### VM消息-Actor方法调用
消息是两个参与者之间进行通信的单位，因此是状态变化的根本原因。一条消息结合了：  
从发送方转移到收方的令牌金额  
具有在接收方上调用的参数的方法。  

Actor代码可以在处理收到的消息时将其他消息发送给其他Actor。消息被同步处理：参与者在恢复控制之前等待发送的消息完成。

消息的处理消耗了以气体计价的计算和存储定位。消息的气体限制为其计算提供了上限。消息的发件人以其缺定的汽油价格来支付消息执行所消耗的气体单位（包括所有其他嵌套的信息）。区块生产者选择要包含在区块中的消息。并根据每个信息的汽油价格和消耗量获得奖励，从而形成市场。 
#### 消息语法验证
语法无效的消息不得传输，保留在消息池中或包含在块中。  
语法上有效的`UnsignedMessage`:  
1.具有格式正确的非空`To`地址，  
2.具有格式正确的非空`From`地址，  
3.具有非负数`CallSeqNum`，  
4.具有`Value`不小于零且不大于令牌总供给（2e9 * 1e18）,   
5.具有非负数`MethodNum`,  
6.`Params`仅当`MethodNum`为零时才具有非空，  
7.具有非负数`GasPrice`,  
8.具有`GasLimit`至少等于与消息的序列化字节关联的气体消耗的值，  
9.具有`GasLimit`不大于区块气体限制网络参数的值。  

当单独发送时（在包含在块中之前）`SignedMessage`，无论使用哪种签名，都将消息打包为有效的签名信息：  
序列化的总大小不大于`message.MessageMaxSize`。
#### 消息语义验证
语义验证是指需要消息本身之外的消息的验证。

语义上有效的`SigneMessage`必须带有签名，以验证有效载荷是否已被`From`地址标识的账户执行者的公钥签名。请注意，当该`From`地址是ID地址时，必须在块所标识的父状态下的发送账户参与者的状态下查找公钥。  

注意：发送方必须以包含消息的块所标识色父级状态存在。这意味着单个块包含创建新账户Actor的消息和来自同一Actor的消息是无效的。请参与者的第一条消息必须等到下一个纪元。消息池可能会排除来自Actor的，尚未处于链状状态的消息。

消息没有进一步的语义验证，可能导致包含该消息的块无效。每个语法有效且正确签名的消息都可以包含在一个块中，并会从执行中产生一个收据。但是，消息可能无法执行到完成，在这种情况下，他不会影响所需的状态更改。

这种“无消息语义验证“策略的原因是，在消息作为提示集的一部分执行之前，将不知道消息将应用于的状态。块生产者不知道在提示集是否有另一个块会在其之前，因此从声明的父状态更改了该块消息将应用到的状态。  

```
import filcrypto "github.com/filecoin-project/specs/algorithms/crypto"
import addr "github.com/filecoin-project/specs/systems/filecoin_vm/actor/address"
import actor "github.com/filecoin-project/specs/systems/filecoin_vm/actor"
import abi "github.com/filecoin-project/specs/actors/abi"

// GasAmount is a quantity of gas.
type GasAmount struct {
    value                BigInt

    Add(GasAmount)       GasAmount
    Subtract(GasAmount)  GasAmount
    SubtractIfNonnegative(GasAmount) (ret GasAmount, ok bool)
    LessThan(GasAmount) bool
    Equals(GasAmount) bool
    Scale(int) GasAmount
}

type UnsignedMessage struct {
    // Address of the receiving actor.
    To          addr.Address
    // Address of the sending actor.
    From        addr.Address
    // Expected CallSeqNum of the sending actor (only for top-level messages).
    CallSeqNum  actor.CallSeqNum

    // Amount of value to transfer from sender's to receiver's balance.
    Value       abi.TokenAmount

    // Optional method to invoke on receiver, zero for a plain value send.
    Method      abi.MethodNum
    /// Serialized parameters to the method (if method is non-zero).
    Params      abi.MethodParams

    // GasPrice is a Gas-to-FIL cost
    GasPrice    abi.TokenAmount
    GasLimit    GasAmount
}  // representation tuple

type SignedMessage struct {
    Message    UnsignedMessage
    Signature  filcrypto.Signature
}  // representation tuple
```
```
package message

import (
	filcrypto "github.com/filecoin-project/specs/algorithms/crypto"
	util "github.com/filecoin-project/specs/util"
)

var IMPL_FINISH = util.IMPL_FINISH

type Serialization = util.Serialization

// The maximum serialized size of a SignedMessage.
const MessageMaxSize = 32 * 1024

func SignedMessage_Make(message UnsignedMessage, signature filcrypto.Signature) SignedMessage {
	return &SignedMessage_I{
		Message_:   message,
		Signature_: signature,
	}
}

func Sign(message UnsignedMessage, keyPair filcrypto.SigKeyPair) (SignedMessage, error) {
	sig, err := filcrypto.Sign(keyPair, util.Bytes(Serialize_UnsignedMessage(message)))
	if err != nil {
		return nil, err
	}
	return SignedMessage_Make(message, sig), nil
}

func SignatureVerificationError() error {
	IMPL_FINISH()
	panic("")
}

func Verify(message SignedMessage, publicKey filcrypto.PublicKey) (UnsignedMessage, error) {
	m := util.Bytes(Serialize_UnsignedMessage(message.Message()))
	sigValid, err := filcrypto.Verify(publicKey, message.Signature(), m)
	if err != nil {
		return nil, err
	}
	if !sigValid {
		return nil, SignatureVerificationError()
	}
	return message.Message(), nil
}

func (x *GasAmount_I) Add(y GasAmount) GasAmount {
	IMPL_FINISH()
	panic("")
}

func (x *GasAmount_I) Subtract(y GasAmount) GasAmount {
	IMPL_FINISH()
	panic("")
}

func (x *GasAmount_I) SubtractIfNonnegative(y GasAmount) (ret GasAmount, ok bool) {
	ret = x.Subtract(y)
	ok = true
	if ret.LessThan(GasAmount_Zero()) {
		ret = x
		ok = false
	}
	return
}

func (x *GasAmount_I) LessThan(y GasAmount) bool {
	IMPL_FINISH()
	panic("")
}

func (x *GasAmount_I) Equals(y GasAmount) bool {
	IMPL_FINISH()
	panic("")
}

func (x *GasAmount_I) Scale(count int) GasAmount {
	IMPL_FINISH()
	panic("")
}

func GasAmount_Affine(b GasAmount, x int, m GasAmount) GasAmount {
	return b.Add(m.Scale(x))
}

func GasAmount_Zero() GasAmount {
	return GasAmount_FromInt(0)
}

func GasAmount_FromInt(x int) GasAmount {
	IMPL_FINISH()
	panic("")
}

func GasAmount_SentinelUnlimited() GasAmount {
	// Amount of gas larger than any feasible execution; meant to indicated unlimited gas
	// (e.g., for builtin system method invocations).
	return GasAmount_FromInt(1).Scale(1e9).Scale(1e9) // 10^18
}
```
### VM运行时环境（在VM内部）
#### 收据
`MessageReceipt`包含一个顶层消息执行的结果。

语法有效的收据具有：  
一个非负`ExitCode`,  
`ReturnValue`仅当退出代码为零时为非空，  
非负数`GasUsed`。
#### vm/runtime接口
```
import actor "github.com/filecoin-project/specs/systems/filecoin_vm/actor"
import abi "github.com/filecoin-project/specs/actors/abi"
import addr "github.com/filecoin-project/specs/systems/filecoin_vm/actor/address"
import exitcode "github.com/filecoin-project/specs/systems/filecoin_vm/runtime/exitcode"
import filcrypto "github.com/filecoin-project/specs/algorithms/crypto"
import indices "github.com/filecoin-project/specs/systems/filecoin_vm/indices"
import ipld "github.com/filecoin-project/specs/libraries/ipld"
import msg "github.com/filecoin-project/specs/systems/filecoin_vm/message"

// Runtime is the VM's internal runtime object.
// this is everything that is accessible to actors, beyond parameters.
type Runtime interface {
    CurrEpoch() abi.ChainEpoch

    // Randomness returns a (pseudo)random string for the given epoch and tag.
    Randomness(tag filcrypto.DomainSeparationTag, epoch abi.ChainEpoch) abi.Randomness
    RandomnessWithAuxSeed(
        tag      filcrypto.DomainSeparationTag
        epoch    abi.ChainEpoch
        auxSeed  util.Serialization
    ) abi.Randomness

    // The address of the immediate calling actor.
    // Not necessarily the actor in the From field of the initial on-chain Message.
    // Always an ID-address.
    ImmediateCaller() addr.Address
    ValidateImmediateCallerIs(caller addr.Address)
    ValidateImmediateCallerInSet(callers [addr.Address])
    ValidateImmediateCallerAcceptAnyOfType(type_ abi.ActorCodeID)
    ValidateImmediateCallerAcceptAnyOfTypes(types [abi.ActorCodeID])
    ValidateImmediateCallerAcceptAny()
    ValidateImmediateCallerMatches(CallerPattern)

    // The address of the actor receiving the message. Always an ID-address.
    CurrReceiver()         addr.Address

    // The actor who mined the block in which the initial on-chain message appears.
    // Always an ID-address.
    ToplevelBlockWinner()  addr.Address

    AcquireState()         ActorStateHandle

    SuccessReturn()        InvocOutput
    ValueReturn(Bytes)     InvocOutput

    // Throw an error indicating a failure condition has occurred, from which the given actor
    // code is unable to recover.
    Abort(errExitCode exitcode.ExitCode, msg string)

    // Calls Abort with InvalidArguments_User.
    AbortArgMsg(msg string)
    AbortArg()

    // Calls Abort with InconsistentState_User.
    AbortStateMsg(msg string)
    AbortState()

    // Calls Abort with InsufficientFunds_User.
    AbortFundsMsg(msg string)
    AbortFunds()

    // Calls Abort with RuntimeAPIError.
    // For internal use only (not in actor code).
    AbortAPI(msg string)

    // Check that the given condition is true (and call Abort if not).
    Assert(bool)

    CurrentBalance()  abi.TokenAmount
    ValueReceived()   abi.TokenAmount

    // Look up the current values of several system-wide economic indices.
    CurrIndices()     indices.Indices

    // Look up the code ID of a given actor address.
    GetActorCodeID(addr addr.Address) (ret abi.ActorCodeID, ok bool)

    // Run a (pure function) computation, consuming the gas cost associated with that function.
    // This mechanism is intended to capture the notion of an ABI between the VM and native
    // functions, and should be used for any function whose computation is expensive.
    Compute(ComputeFunctionID, args [util.Any]) util.Any

    // Sends a message to another actor.
    // If the invoked method does not return successfully, this caller will be aborted too.
    SendPropagatingErrors(input InvocInput) InvocOutput
    Send(
        toAddr     addr.Address
        methodNum  abi.MethodNum
        params     abi.MethodParams
        value      abi.TokenAmount
    ) InvocOutput
    SendQuery(
        toAddr     addr.Address
        methodNum  abi.MethodNum
        params     abi.MethodParams
    ) util.Serialization
    SendFunds(toAddr addr.Address, value abi.TokenAmount)

    // Sends a message to another actor, trapping an unsuccessful execution.
    // This may only be invoked by the singleton Cron actor.
    SendCatchingErrors(input InvocInput) (output InvocOutput, exitCode exitcode.ExitCode)

    // Computes an address for a new actor. The returned address is intended to uniquely refer to
    // the actor even in the event of a chain re-org (whereas an ID-address might refer to a
    // different actor after messages are re-ordered).
    // Always an ActorExec address.
    NewActorAddress() addr.Address

    // Creates an actor in the state tree, with empty state. May only be called by InitActor.
    CreateActor(
        // The new actor's code identifier.
        codeId   abi.ActorCodeID
        // Address under which the new actor's state will be stored. Must be an ID-address.
        address  addr.Address
    )

    // Deletes an actor in the state tree. May only be called by the actor itself,
    // or by StoragePowerActor in the case of StorageMinerActors.
    DeleteActor(address addr.Address)

    // Retrieves and deserializes an object from the store into o. Returns whether successful.
    IpldGet(c ipld.CID, o ipld.Object) bool
    // Serializes and stores an object, returning its CID.
    IpldPut(x ipld.Object) ipld.CID
}

type InvocInput struct {
    To      addr.Address
    Method  abi.MethodNum
    Params  abi.MethodParams
    Value   abi.TokenAmount
}

type InvocOutput struct {
    ReturnValue Bytes
}

type MessageReceipt struct {
    ExitCode     exitcode.ExitCode
    ReturnValue  Bytes
    GasUsed      msg.GasAmount
}  // representation tuple

type ActorStateHandle interface {
    UpdateRelease(newStateCID actor.ActorSubstateCID)
    Release(checkStateCID actor.ActorSubstateCID)
    Take() actor.ActorSubstateCID
}

type ComputeFunctionID enum {
    VerifySignature
}
```
#### vm/runtime实作
...
#### 代码加载
...
#### VM退出代码常量
```
type ExitCode union {
    IsSuccess()          bool
    IsError()            bool
    AllowsStateUpdate()  bool
    Equals(ExitCode)     bool

    Success              struct {}
    SystemError          SystemErrorCode
    UserDefinedError     UVarint
}
```
```
package exitcode

import (
	"fmt"

	util "github.com/filecoin-project/specs/util"
)

type SystemErrorCode int
type UserDefinedErrorCode int

const (
	// TODO: remove once canonical error codes are finalized
	SystemErrorCode_Placeholder      = SystemErrorCode(-(1 << 30))
	UserDefinedErrorCode_Placeholder = UserDefinedErrorCode(-(1 << 30))
)

var IMPL_FINISH = util.IMPL_FINISH
var TODO = util.TODO

// TODO: assign all of these.
const (
	// ActorNotFound represents a failure to find an actor.
	ActorNotFound = SystemErrorCode_Placeholder + iota

	// ActorCodeNotFound represents a failure to find the code for a
	// particular actor in the VM registry.
	ActorCodeNotFound

	// InvalidMethod represents a failure to find a method in
	// an actor
	InvalidMethod

	// InvalidArgumentsSystem indicates that a method was called with the incorrect
	// number of arguments, or that its arguments did not satisfy its
	// preconditions
	InvalidArguments_System

	// InsufficientFunds represents a failure to apply a message, as
	// it did not carry sufficient funds for its application.
	InsufficientFunds_System

	// InvalidCallSeqNum represents a message invocation out of sequence.
	// This happens when message.CallSeqNum is not exactly actor.CallSeqNum + 1
	InvalidCallSeqNum

	// OutOfGas is returned when the execution of an actor method
	// (including its subcalls) uses more gas than initially allocated.
	OutOfGas

	// RuntimeAPIError is returned when an actor method invocation makes a call
	// to the runtime that does not satisfy its preconditions.
	RuntimeAPIError

	// RuntimeAssertFailure is returned when an actor method invocation calls
	// rt.Assert with a false condition.
	RuntimeAssertFailure

	// MethodSubcallError is returned when an actor method's Send call has
	// returned with a failure error code (and the Send call did not specify
	// to ignore errors).
	MethodSubcallError
)

const (
	InsufficientFunds_User = UserDefinedErrorCode_Placeholder + iota
	InvalidArguments_User
	InconsistentState_User

	InvalidSectorPacking
	SealVerificationFailed
	PoStVerificationFailed
	DeadlineExceeded
	InsufficientPledgeCollateral
)

func OK() ExitCode {
	return ExitCode_Make_Success(&ExitCode_Success_I{})
}

func SystemError(x SystemErrorCode) ExitCode {
	return ExitCode_Make_SystemError(ExitCode_SystemError(x))
}

func (x *ExitCode_I) IsSuccess() bool {
	return x.Which() == ExitCode_Case_Success
}

func (x *ExitCode_I) IsError() bool {
	return !x.IsSuccess()
}

func (x *ExitCode_I) AllowsStateUpdate() bool {
	return x.IsSuccess()
}

func (x *ExitCode_I) Equals(ExitCode) bool {
	IMPL_FINISH()
	panic("")
}

func EnsureErrorCode(x ExitCode) ExitCode {
	if !x.IsError() {
		// Throwing an error with a non-error exit code is itself an error
		x = SystemError(RuntimeAPIError)
	}
	return x
}

type RuntimeError struct {
	ExitCode ExitCode
	ErrMsg   string
}

func (x *RuntimeError) String() string {
	ret := fmt.Sprintf("Runtime error: %v", x.ExitCode)
	if x.ErrMsg != "" {
		ret += fmt.Sprintf(" (\"%v\")", x.ErrMsg)
	}
	return ret
}

func RuntimeError_Make(exitCode ExitCode, errMsg string) *RuntimeError {
	exitCode = EnsureErrorCode(exitCode)
	return &RuntimeError{
		ExitCode: exitCode,
		ErrMsg:   errMsg,
	}
}

func UserDefinedError(e UserDefinedErrorCode) ExitCode {
	return ExitCode_Make_UserDefinedError(ExitCode_UserDefinedError(e))
}
```
#### VM气体成本常数
```
package runtime

import (
	abi "github.com/filecoin-project/specs/actors/abi"
	actor "github.com/filecoin-project/specs/systems/filecoin_vm/actor"
	msg "github.com/filecoin-project/specs/systems/filecoin_vm/message"
	util "github.com/filecoin-project/specs/util"
)

type Bytes = util.Bytes

var TODO = util.TODO

var (
	// TODO: assign all of these.
	GasAmountPlaceholder                 = msg.GasAmount_FromInt(1)
	GasAmountPlaceholder_UpdateStateTree = GasAmountPlaceholder
)

var (
	///////////////////////////////////////////////////////////////////////////
	// System operations
	///////////////////////////////////////////////////////////////////////////

	// Gas cost charged to the originator of an on-chain message (regardless of
	// whether it succeeds or fails in application) is given by:
	//   OnChainMessageBase + len(serialized message)*OnChainMessagePerByte
	// Together, these account for the cost of message propagation and validation,
	// up to but excluding any actual processing by the VM.
	// This is the cost a block producer burns when including an invalid message.
	OnChainMessageBase    = GasAmountPlaceholder
	OnChainMessagePerByte = GasAmountPlaceholder

	// Gas cost charged to the originator of a non-nil return value produced
	// by an on-chain message is given by:
	//   len(return value)*OnChainReturnValuePerByte
	OnChainReturnValuePerByte = GasAmountPlaceholder

	// Gas cost for any message send execution(including the top-level one
	// initiated by an on-chain message).
	// This accounts for the cost of loading sender and receiver actors and
	// (for top-level messages) incrementing the sender's sequence number.
	// Load and store of actor sub-state is charged separately.
	SendBase = GasAmountPlaceholder

	// Gas cost charged, in addition to SendBase, if a message send
	// is accompanied by any nonzero currency amount.
	// Accounts for writing receiver's new balance (the sender's state is
	// already accounted for).
	SendTransferFunds = GasAmountPlaceholder

	// Gas cost charged, in addition to SendBase, if a message invokes
	// a method on the receiver.
	// Accounts for the cost of loading receiver code and method dispatch.
	SendInvokeMethod = GasAmountPlaceholder

	// Gas cost (Base + len*PerByte) for any Get operation to the IPLD store
	// in the runtime VM context.
	IpldGetBase    = GasAmountPlaceholder
	IpldGetPerByte = GasAmountPlaceholder

	// Gas cost (Base + len*PerByte) for any Put operation to the IPLD store
	// in the runtime VM context.
	//
	// Note: these costs should be significantly higher than the costs for Get
	// operations, since they reflect not only serialization/deserialization
	// but also persistent storage of chain data.
	IpldPutBase    = GasAmountPlaceholder
	IpldPutPerByte = GasAmountPlaceholder

	// Gas cost for updating an actor's substate (i.e., UpdateRelease).
	// This is in addition to a per-byte fee for the state as for IPLD Get/Put.
	UpdateActorSubstate = GasAmountPlaceholder_UpdateStateTree

	// Gas cost for creating a new actor (via InitActor's Exec method).
	// Actor sub-state is charged separately.
	ExecNewActor = GasAmountPlaceholder

	// Gas cost for deleting an actor.
	DeleteActor = GasAmountPlaceholder

	///////////////////////////////////////////////////////////////////////////
	// Pure functions (VM ABI)
	///////////////////////////////////////////////////////////////////////////

	// Gas cost charged per public-key cryptography operation (e.g., signature
	// verification).
	PublicKeyCryptoOp = GasAmountPlaceholder
)

func OnChainMessage(onChainMessageLen int) msg.GasAmount {
	return msg.GasAmount_Affine(OnChainMessageBase, onChainMessageLen, OnChainMessagePerByte)
}

func OnChainReturnValue(returnValue Bytes) msg.GasAmount {
	retLen := 0
	if returnValue != nil {
		retLen = len(returnValue)
	}

	return msg.GasAmount_Affine(msg.GasAmount_Zero(), retLen, OnChainReturnValuePerByte)
}

func IpldGet(dataSize int) msg.GasAmount {
	return msg.GasAmount_Affine(IpldGetBase, dataSize, IpldGetPerByte)
}

func IpldPut(dataSize int) msg.GasAmount {
	return msg.GasAmount_Affine(IpldPutBase, dataSize, IpldPutPerByte)
}

func InvokeMethod(value abi.TokenAmount, method abi.MethodNum) msg.GasAmount {
	ret := SendBase
	if value != abi.TokenAmount(0) {
		ret = ret.Add(SendTransferFunds)
	}
	if method != actor.MethodSend {
		ret = ret.Add(SendInvokeMethod)
	}
	return ret
}
```
### 系统角色
VM处理需要两个系统参与者：  
CronActor-在每个时期运行关键功能  
InitActor-初始化新角色，记录网络名称  
还有另外两个VM级别参与者：  
AccounterActor-用于用户账户（非单个）  
RewardActor-用于块奖励和令牌归属（单个）。
#### 初始化演员
```
import addr "github.com/filecoin-project/specs/systems/filecoin_vm/actor/address"
import abi "github.com/filecoin-project/specs/actors/abi"
import vmr "github.com/filecoin-project/specs/systems/filecoin_vm/runtime"

type InitActorState struct {
    // responsible for create new actors
    AddressMap   {addr.Address: addr.ActorID}
    NextID       addr.ActorID
    NetworkName  string

    // Allocates a new ID and maps another address to it. Returns the ID-address.
    MapAddressToNewID(address addr.Address) addr.Address
    // Resolves an address to an ID-address, if possible. Returns the argument if un-mapped.
    ResolveAddress(address addr.Address) addr.Address
}

type InitActorCode struct {
    Constructor(r vmr.Runtime, networkName string)
    Exec(r vmr.Runtime, code abi.ActorCodeID, params abi.MethodParams) addr.Address

    // This method is disabled until proven necessary.
    //GetActorIDForAddress(r vmr.Runtime, address addr.Address) addr.ActorID
}
```
```
package init

import (
	abi "github.com/filecoin-project/specs/actors/abi"
	builtin "github.com/filecoin-project/specs/actors/builtin"
	vmr "github.com/filecoin-project/specs/actors/runtime"
	autil "github.com/filecoin-project/specs/actors/util"
	ipld "github.com/filecoin-project/specs/libraries/ipld"
	actor "github.com/filecoin-project/specs/systems/filecoin_vm/actor"
	addr "github.com/filecoin-project/specs/systems/filecoin_vm/actor/address"
)

type InvocOutput = vmr.InvocOutput
type Runtime = vmr.Runtime
type Bytes = abi.Bytes

var AssertMsg = autil.AssertMsg

func (a *InitActorCode_I) Constructor(rt Runtime) InvocOutput {
	rt.ValidateImmediateCallerIs(addr.SystemActorAddr)
	h := rt.AcquireState()
	st := &InitActorState_I{
		AddressMap_:  map[addr.Address]addr.ActorID{}, // TODO: HAMT
		NextID_:      addr.ActorID(addr.FirstNonSingletonActorId),
		NetworkName_: vmr.NetworkName(),
	}
	UpdateRelease(rt, h, st)
	return rt.ValueReturn(nil)
}

func (a *InitActorCode_I) Exec(rt Runtime, execCodeID abi.ActorCodeID, constructorParams abi.MethodParams) InvocOutput {
	rt.ValidateImmediateCallerAcceptAny()
	callerCodeID, ok := rt.GetActorCodeID(rt.ImmediateCaller())
	AssertMsg(ok, "no code for actor at %s", rt.ImmediateCaller())
	if !_codeIDSupportsExec(callerCodeID, execCodeID) {
		rt.AbortArgMsg("Caller type cannot create an actor of requested type")
	}

	// Compute a re-org-stable address.
	// This address exists for use by messages coming from outside the system, in order to
	// stably address the newly created actor even if a chain re-org causes it to end up with
	// a different ID.
	newAddr := rt.NewActorAddress()

	// Allocate an ID for this actor.
	// Store mapping of pubkey or actor address to actor ID
	h, st := _loadState(rt)
	idAddr := st.MapAddressToNewID(newAddr)
	UpdateRelease(rt, h, st)

	// Create an empty actor.
	rt.CreateActor(execCodeID, idAddr)

	// Invoke constructor. If construction fails, the error should propagate and cause
	// Exec to fail too.
	rt.SendPropagatingErrors(&vmr.InvocInput_I{
		To_:     idAddr,
		Method_: actor.MethodConstructor,
		Params_: constructorParams,
		Value_:  rt.ValueReceived(),
	})

	return rt.ValueReturn(
		Bytes(addr.Serialize_Address_Compact(idAddr)))
}

// This method is disabled until proven necessary.
//func (a *InitActorCode_I) GetActorIDForAddress(rt Runtime, address addr.Address) InvocOutput {
//	h, st := _loadState(rt)
//	actorID := st.AddressMap()[address]
//	Release(rt, h, st)
//	return rt.ValueReturn(Bytes(addr.Serialize_ActorID(actorID)))
//}

func (s *InitActorState_I) ResolveAddress(address addr.Address) addr.Address {
	actorID, ok := s.AddressMap()[address]
	if ok {
		return addr.Address_Make_ID(addr.Address_NetworkID_Testnet, actorID)
	}
	return address
}

func (s *InitActorState_I) MapAddressToNewID(address addr.Address) addr.Address {
	actorID := s.NextID_
	s.NextID_++
	s.AddressMap()[address] = actorID
	return addr.Address_Make_ID(addr.Address_NetworkID_Testnet, actorID)
}

func _codeIDSupportsExec(callerCodeID abi.ActorCodeID, execCodeID abi.ActorCodeID) bool {
	if execCodeID == builtin.AccountActorCodeID {
		// Special case: account actors must be created implicitly by sending value;
		// cannot be created via exec.
		return false
	}

	if execCodeID == builtin.PaymentChannelActorCodeID {
		return true
	}

	if execCodeID == builtin.StorageMinerActorCodeID {
		if callerCodeID == builtin.StoragePowerActorCodeID {
			return true
		}
	}

	return false
}

///// Boilerplate /////

func _loadState(rt Runtime) (vmr.ActorStateHandle, InitActorState) {
	h := rt.AcquireState()
	stateCID := ipld.CID(h.Take())
	var state InitActorState_I
	if !rt.IpldGet(stateCID, &state) {
		rt.AbortAPI("state not found")
	}
	return h, &state
}

func Release(rt Runtime, h vmr.ActorStateHandle, st InitActorState) {
	checkCID := actor.ActorSubstateCID(rt.IpldPut(st.Impl()))
	h.Release(checkCID)
}

func UpdateRelease(rt Runtime, h vmr.ActorStateHandle, st InitActorState) {
	newCID := actor.ActorSubstateCID(rt.IpldPut(st.Impl()))
	h.UpdateRelease(newCID)
}

func (st *InitActorState_I) CID() ipld.CID {
	panic("TODO")
}
```
#### CronActor
```
import abi "github.com/filecoin-project/specs/actors/abi"
import addr "github.com/filecoin-project/specs/systems/filecoin_vm/actor/address"
import vmr "github.com/filecoin-project/specs/actors/runtime"

type CronActorState struct {
    // Cron has no internal state
}

type CronTableEntry struct {
    ToAddr     addr.Address
    MethodNum  abi.MethodNum
}

type CronActorCode struct {
    // Entries is a set of actors (and corresponding methods) to call during EpochTick.
    // This can be done a bunch of ways. We do it this way here to make it easy to add
    // a handler to Cron elsewhere in the spec code. How to do this is implementation
    // specific.
    Entries [CronTableEntry]

    // EpochTick executes built-in periodic actions, run at every Epoch.
    // EpochTick(r) is called after all other messages in the epoch have been applied.
    // This can be seen as an implicit last message.
    EpochTick(r vmr.Runtime)
}
```
```
package cron

import actor "github.com/filecoin-project/specs/systems/filecoin_vm/actor"
import abi "github.com/filecoin-project/specs/actors/abi"
import addr "github.com/filecoin-project/specs/systems/filecoin_vm/actor/address"
import vmr "github.com/filecoin-project/specs/actors/runtime"

const (
	Method_CronActor_EpochTick = actor.MethodPlaceholder + iota
)

type InvocOutput = vmr.InvocOutput
type Runtime = vmr.Runtime

func (a *CronActorCode_I) Constructor(rt vmr.Runtime) InvocOutput {
	// Nothing. intentionally left blank.
	rt.ValidateImmediateCallerIs(addr.SystemActorAddr)
	return rt.SuccessReturn()
}

func (a *CronActorCode_I) EpochTick(rt vmr.Runtime) InvocOutput {
	rt.ValidateImmediateCallerIs(addr.SystemActorAddr)

	// a.Entries is basically a static registry for now, loaded
	// in the interpreter static registry.
	for _, entry := range a.Entries() {
		rt.SendCatchingErrors(&vmr.InvocInput_I{
			To_:     entry.ToAddr(),
			Method_: entry.MethodNum(),
			Params_: nil,
			Value_:  abi.TokenAmount(0),
		})
	}

	return rt.SuccessReturn()
}
```
#### AccounActor
```
import addr "github.com/filecoin-project/specs/systems/filecoin_vm/actor/address"

type AccountActorCode struct {}

type AccountActorState struct {
    Address addr.Address
}
```
```
package account

import (
	vmr "github.com/filecoin-project/specs/actors/runtime"
	ipld "github.com/filecoin-project/specs/libraries/ipld"
	addr "github.com/filecoin-project/specs/systems/filecoin_vm/actor/address"
)

type InvocOutput = vmr.InvocOutput

func (a *AccountActorCode_I) Constructor(rt vmr.Runtime) InvocOutput {
	// Nothing. intentionally left blank.
	rt.ValidateImmediateCallerIs(addr.SystemActorAddr)
	return rt.SuccessReturn()
}

func (st *AccountActorState_I) CID() ipld.CID {
	panic("TODO")
}
```
#### 奖励演员
RewardActor是保存未使用和未使用的Filecoin令牌的位置。在创世之初，RewardActor会使用投资者账户，代币和归属时间表进行初始化，该流程是`RewardMap`从所有者地址到`Reward`结构的映射。一个`Reward`结构包含一个`StartEpoch`跟踪`Reward`创建时间的结构，`Value`该结构表示奖励令牌的总数，并且`ReleaseRate`是每个纪元以FIL为单位的线性释放速率。`WithdrawAmount`记录到目前为止已从`Reward`结构中提取了多少令牌。 所有者地址可以调用`WithdrawReward`，它将从到目前为止的`RewardMap`撤回投资者地址拥有的所有既有代币。 当`WithdrawAmount`等于Reward结构中的Value时，即为`RewardRewardMap`。

`RewardMap`也可用于区块奖励铸造中，以保留向协议引入区块奖励归属的灵活性。`MinReward`创建一个新`Reward`结构并将其添加到`RewardMap`中。

```
import vmr "github.com/filecoin-project/specs/actors/runtime"
import abi "github.com/filecoin-project/specs/actors/abi"
import addr "github.com/filecoin-project/specs/systems/filecoin_vm/actor/address"

type VestingFunction enum {
    None
    Linear
    // TODO: potential options
    // PieceWise
    // Quadratic
    // Exponential
}

type Reward struct {
    VestingFunction
    StartEpoch       abi.ChainEpoch
    EndEpoch         abi.ChainEpoch
    Value            abi.TokenAmount
    AmountWithdrawn  abi.TokenAmount

    AmountVested(elapsedEpoch abi.ChainEpoch) abi.TokenAmount
}

// ownerAddr to a collection of Reward
type RewardBalanceAMT {addr.Address: [Reward]}

type RewardActorState struct {
    RewardMap RewardBalanceAMT

    _withdrawReward(rt vmr.Runtime, ownerAddr addr.Address) abi.TokenAmount
}

type RewardActorCode struct {
    Constructor(rt vmr.Runtime)

    // Allocates a block reward to the owner of a miner, less
    // - penalty, which is burnt
    // - any amount of pledge collateral shortfall, which is transferred to storage power actor
    AwardBlockReward(rt vmr.Runtime, miner addr.Address, penalty abi.TokenAmount)

    // withdraw available funds from RewardMap
    WithdrawReward(rt vmr.Runtime)
}
```
```
package reward

import (
	"math"

	abi "github.com/filecoin-project/specs/actors/abi"
	vmr "github.com/filecoin-project/specs/actors/runtime"
	serde "github.com/filecoin-project/specs/actors/serde"
	autil "github.com/filecoin-project/specs/actors/util"
	ipld "github.com/filecoin-project/specs/libraries/ipld"
	actor "github.com/filecoin-project/specs/systems/filecoin_vm/actor"
	addr "github.com/filecoin-project/specs/systems/filecoin_vm/actor/address"
	ai "github.com/filecoin-project/specs/systems/filecoin_vm/actor_interfaces"
)

type InvocOutput = vmr.InvocOutput
type Runtime = vmr.Runtime

var IMPL_FINISH = autil.IMPL_FINISH
var IMPL_TODO = autil.IMPL_TODO
var TODO = autil.TODO

////////////////////////////////////////////////////////////////////////////////
// Boilerplate
////////////////////////////////////////////////////////////////////////////////

func (a *RewardActorCode_I) State(rt Runtime) (vmr.ActorStateHandle, RewardActorState) {
	h := rt.AcquireState()
	stateCID := ipld.CID(h.Take())
	var state RewardActorState_I
	if !rt.IpldGet(stateCID, &state) {
		rt.AbortAPI("state not found")
	}
	return h, &state
}
func UpdateReleaseRewardActorState(rt Runtime, h vmr.ActorStateHandle, st RewardActorState) {
	newCID := actor.ActorSubstateCID(rt.IpldPut(st.Impl()))
	h.UpdateRelease(newCID)
}
func (st *RewardActorState_I) CID() ipld.CID {
	panic("TODO")
}

////////////////////////////////////////////////////////////////////////////////

func (r *Reward_I) AmountVested(elapsedEpoch abi.ChainEpoch) abi.TokenAmount {
	switch r.VestingFunction() {
	case VestingFunction_None:
		return r.Value()
	case VestingFunction_Linear:
		TODO() // BigInt
		vestedProportion := math.Max(1.0, float64(elapsedEpoch)/float64(r.StartEpoch()-r.EndEpoch()))
		return abi.TokenAmount(uint64(r.Value()) * uint64(vestedProportion))
	default:
		return abi.TokenAmount(0)
	}
}

func (st *RewardActorState_I) _withdrawReward(rt vmr.Runtime, ownerAddr addr.Address) abi.TokenAmount {

	rewards, found := st.RewardMap()[ownerAddr]
	if !found {
		rt.AbortStateMsg("ra._withdrawReward: ownerAddr not found in RewardMap.")
	}

	rewardToWithdrawTotal := abi.TokenAmount(0)
	indicesToRemove := make([]int, len(rewards))

	for i, r := range rewards {
		elapsedEpoch := rt.CurrEpoch() - r.StartEpoch()
		unlockedReward := r.AmountVested(elapsedEpoch)
		withdrawableReward := unlockedReward - r.AmountWithdrawn()

		if withdrawableReward < 0 {
			rt.AbortStateMsg("ra._withdrawReward: negative withdrawableReward.")
		}

		r.Impl().AmountWithdrawn_ = unlockedReward // modify rewards in place
		rewardToWithdrawTotal += withdrawableReward

		if r.AmountWithdrawn() == r.Value() {
			indicesToRemove = append(indicesToRemove, i)
		}
	}

	updatedRewards := removeIndices(rewards, indicesToRemove)
	st.RewardMap()[ownerAddr] = updatedRewards

	return rewardToWithdrawTotal
}

func (a *RewardActorCode_I) Constructor(rt vmr.Runtime) InvocOutput {
	rt.ValidateImmediateCallerIs(addr.SystemActorAddr)

	// initialize Reward Map with investor accounts
	panic("TODO")
}

func (a *RewardActorCode_I) AwardBlockReward(
	rt vmr.Runtime,
	miner addr.Address,
	penalty abi.TokenAmount,
	minerNominalPower abi.StoragePower,
	currPledge abi.TokenAmount,
) {
	rt.ValidateImmediateCallerIs(addr.SystemActorAddr)

	inds := rt.CurrIndices()
	pledgeReq := inds.PledgeCollateralReq(minerNominalPower)
	currReward := inds.GetCurrBlockRewardForMiner(minerNominalPower, currPledge)
	TODO()                                                                              // BigInt
	underPledge := math.Max(float64(abi.TokenAmount(0)), float64(pledgeReq-currPledge)) // 0 if over collateralized
	rewardToGarnish := math.Min(float64(currReward), float64(underPledge))

	TODO()
	// handle penalty here
	// also handle penalty greater than reward
	actualReward := currReward - abi.TokenAmount(rewardToGarnish)
	if rewardToGarnish > 0 {
		// Send fund to SPA for collateral
		rt.Send(
			addr.StoragePowerActorAddr,
			ai.Method_StoragePowerActor_AddBalance,
			serde.MustSerializeParams(miner),
			abi.TokenAmount(rewardToGarnish),
		)
	}

	h, st := a.State(rt)
	if actualReward > 0 {
		// put Reward into RewardMap
		newReward := &Reward_I{
			StartEpoch_:      rt.CurrEpoch(),
			EndEpoch_:        rt.CurrEpoch(),
			Value_:           actualReward,
			AmountWithdrawn_: abi.TokenAmount(0),
			VestingFunction_: VestingFunction_None,
		}
		rewards, found := st.RewardMap()[miner]
		if !found {
			rewards = make([]Reward, 0)
		}
		rewards = append(rewards, newReward)
		st.Impl().RewardMap_[miner] = rewards
	}
	UpdateReleaseRewardActorState(rt, h, st)
}

func (a *RewardActorCode_I) WithdrawReward(rt vmr.Runtime) {
	vmr.RT_ValidateImmediateCallerIsSignable(rt)
	ownerAddr := rt.ImmediateCaller()

	h, st := a.State(rt)

	// withdraw available funds from RewardMap
	withdrawableReward := st._withdrawReward(rt, ownerAddr)
	UpdateReleaseRewardActorState(rt, h, st)

	rt.SendFunds(ownerAddr, withdrawableReward)
}

func removeIndices(rewards []Reward, indices []int) []Reward {
	// remove fully paid out Rewards by indices
	panic("TODO")
}
```
### VM解释器-消息调用（外部VM）
VM解释器根据提示集在其父状态上的提示集协调消息的执行，从而产生新状态和一系列消息回执。此新状态的CID和收据集合的CID包含在后续纪元的块中，这些纪元必须同意这些CID才能形成新的提示集。

每个状态更改都由消息的执行来驱动。提示集中所有块中的消息都必须执行才能产生下一个状态。来自第一个块闳的所有消息均在技巧集中 的第二个和后续块的消息之前执行。对于每个块，首先执行BLS聚合的消息，然后执行SECP签名名额消息。
#### 隐式消息
除了显式包含在每个块中的消息之外，隐含消息还会在每个时期对状态进行一些更改。隐式消息不在节点之间传输，而是有解释器在评估时构造的。

对于提示集中的每个块，隐式消息:

调用区块生产者的旷工Actor来处理（已验证的）选举PoSt提交，作为区块中的第一条消息；  
调用奖励参与者将区块奖励支付给矿工的所以者账户，作为区块中的最终消息；   
对于每个提示集，一个隐式消息：

调用cron actor来处理自动支票和付款，作为提示集中的最后一条消息。

所有隐式消息的构造`From`地址都是杰出的系统账户参与者。他们指定的汽油价格为零，但必须包括在计算中。为了计算新状态，他们必须成功（退出代码为零）。隐式邮件的收据不包括在收据列表中；只有明确的消息才有明确的回执。