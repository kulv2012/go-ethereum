// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package p2p implements the Ethereum p2p network protocols.
package p2p

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/discv5"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

const (
	defaultDialTimeout = 15 * time.Second

	// Connectivity defaults.
	maxActiveDialTasks     = 16
	defaultMaxPendingPeers = 50
	defaultDialRatio       = 3

	// Maximum time allowed for reading a complete message.
	// This is effectively the amount of time a connection can be idle.
	frameReadTimeout = 30 * time.Second

	// Maximum amount of time allowed for writing a complete message.
	frameWriteTimeout = 20 * time.Second
)

var errServerStopped = errors.New("server stopped")

// Config holds Server options.
type Config struct {
	// This field must be set to a valid secp256k1 private key.
	PrivateKey *ecdsa.PrivateKey `toml:"-"`

	// MaxPeers is the maximum number of peers that can be
	// connected. It must be greater than zero.
	MaxPeers int

	// MaxPendingPeers is the maximum number of peers that can be pending in the
	// handshake phase, counted separately for inbound and outbound connections.
	// Zero defaults to preset values.
	MaxPendingPeers int `toml:",omitempty"`

	// DialRatio controls the ratio of inbound to dialed connections.
	// Example: a DialRatio of 2 allows 1/2 of connections to be dialed.
	// Setting DialRatio to zero defaults it to 3.
	DialRatio int `toml:",omitempty"`

	// NoDiscovery can be used to disable the peer discovery mechanism.
	// Disabling is useful for protocol debugging (manual topology).
	NoDiscovery bool

	// DiscoveryV5 specifies whether the the new topic-discovery based V5 discovery
	// protocol should be started or not.
	//参数 --v5disc 控制是否使用V5版发现机制 
	DiscoveryV5 bool `toml:",omitempty"`

	// Name sets the node name of this server.
	// Use common.MakeName to create a name that follows existing conventions.
	Name string `toml:"-"`

	// BootstrapNodes are used to establish connectivity
	// with the rest of the network.
	BootstrapNodes []*discover.Node

	// BootstrapNodesV5 are used to establish connectivity
	// with the rest of the network using the V5 discovery
	// protocol.
	BootstrapNodesV5 []*discv5.Node `toml:",omitempty"`

	// Static nodes are used as pre-configured connections which are always
	// maintained and re-connected on disconnects.
	StaticNodes []*discover.Node

	// Trusted nodes are used as pre-configured connections which are always
	// allowed to connect, even above the peer limit.
	TrustedNodes []*discover.Node

	// Connectivity can be restricted to certain IP networks.
	// If this option is set to a non-nil value, only hosts which match one of the
	// IP networks contained in the list are considered.
	NetRestrict *netutil.Netlist `toml:",omitempty"`

	// NodeDatabase is the path to the database containing the previously seen
	// live nodes in the network.
	NodeDatabase string `toml:",omitempty"`

	// Protocols should contain the protocols supported
	// by the server. Matching protocols are launched for
	// each peer.
	//支持的协议， 空跑的话就是：  {Name:eth Version:63 Length:17 Run:0xae30b0 NodeInfo:0xae3300 PeerInfo:0xae3360} {Name:eth Version:62 Length:8 Run:0xae30b0 NodeInfo:0xae3300 PeerInfo:0xae3360}
	Protocols []Protocol `toml:"-"`

	// If ListenAddr is set to a non-nil address, the server
	// will listen for incoming connections.
	//
	// If the port is zero, the operating system will pick a port. The
	// ListenAddr field will be updated with the actual address when
	// the server is started.
	ListenAddr string

	// If set to a non-nil value, the given NAT port mapper
	// is used to make the listening port available to the
	// Internet.
	//一个NAT网络实现，内网映射到外网服务
	NAT nat.Interface `toml:",omitempty"`

	// If Dialer is set to a non-nil value, the given Dialer
	// is used to dial outbound peer connections.
	Dialer NodeDialer `toml:"-"`

	// If NoDial is true, the server will not dial any peers.
	NoDial bool `toml:",omitempty"`

	// If EnableMsgEvents is set then the server will emit PeerEvents
	// whenever a message is sent to or received from a peer
	EnableMsgEvents bool

	// Logger is a custom logger to use with the p2p.Server.
	Logger log.Logger `toml:",omitempty"`
}

// Server manages all peer connections.
//这是一个P2P的核心结构，里面包括一个udp服务发现结构ntab以及tcp监听功能， 就是listener
//UDP用来发现服务，TCP用来建立数据传输连接
type Server struct {
	// Config fields may not be modified while the server is running.
	Config

	// Hooks for testing. These are useful because we can inhibit
	// the whole protocol stack.
	//下面等于newRLPX, 采用Rlpx加密协议进行加密，用在TCP端口上
	newTransport func(net.Conn) transport
	newPeerHook  func(*Peer)

	lock    sync.Mutex // protects running
	running bool

	//服务发现结构，实际上是newUDP(c, cfg)
	ntab         discoverTable
	listener     net.Listener //TCP 监听结构
	ourHandshake *protoHandshake
	lastLookup   time.Time
	DiscV5       *discv5.Network

	// These are for Peers, PeerCount (and nothing else).
	peerOp     chan peerOpFunc
	peerOpDone chan struct{}

	//下面是一堆用来通信的管道
	quit          chan struct{}
	addstatic     chan *discover.Node
	removestatic  chan *discover.Node
	posthandshake chan *conn
	addpeer       chan *conn
	delpeer       chan peerDrop
	loopWG        sync.WaitGroup // loop, listenLoop
	peerFeed      event.Feed
	log           log.Logger
}

type peerOpFunc func(map[discover.NodeID]*Peer)

type peerDrop struct {
	*Peer
	err       error
	requested bool // true if signaled by the peer
}

type connFlag int

const (
	dynDialedConn connFlag = 1 << iota
	staticDialedConn
	inboundConn
	trustedConn
)

// conn wraps a network connection with information gathered
// during the two handshakes.
type conn struct {
	fd net.Conn
	transport  //这是一个重要的接口，包含网络读写的方法
	flags connFlag
	cont  chan error      // The run loop uses cont to signal errors to SetupConn.
	id    discover.NodeID // valid after the encryption handshake
	caps  []Cap           // valid after the protocol handshake
	name  string          // valid after the protocol handshake
}

type transport interface {
	// The two handshakes.
	doEncHandshake(prv *ecdsa.PrivateKey, dialDest *discover.Node) (discover.NodeID, error)
	doProtoHandshake(our *protoHandshake) (*protoHandshake, error)
	// The MsgReadWriter can only be used after the encryption
	// handshake has completed. The code uses conn.id to track this
	// by setting it to a non-nil value after the encryption handshake.
	MsgReadWriter  //真正的消息读写方法
	// transports must provide Close because we use MsgPipe in some of
	// the tests. Closing the actual network connection doesn't do
	// anything in those tests because NsgPipe doesn't use it.
	close(err error)
}

func (c *conn) String() string {
	s := c.flags.String()
	if (c.id != discover.NodeID{}) {
		s += " " + c.id.String()
	}
	s += " " + c.fd.RemoteAddr().String()
	return s
}

func (f connFlag) String() string {
	s := ""
	if f&trustedConn != 0 {
		s += "-trusted"
	}
	if f&dynDialedConn != 0 {
		s += "-dyndial"
	}
	if f&staticDialedConn != 0 {
		s += "-staticdial"
	}
	if f&inboundConn != 0 {
		s += "-inbound"
	}
	if s != "" {
		s = s[1:]
	}
	return s
}

func (c *conn) is(f connFlag) bool {
	return c.flags&f != 0
}

// Peers returns all connected peers.
func (srv *Server) Peers() []*Peer {
	//通过管道，在主协程总执行匿名函数获取当前所有的peers 
	var ps []*Peer
	select {
	// Note: We'd love to put this function into a variable but
	// that seems to cause a weird compiler error in some
	// environments.
	case srv.peerOp <- func(peers map[discover.NodeID]*Peer) {
		for _, p := range peers {
			ps = append(ps, p)
		}
	}:
		<-srv.peerOpDone
	case <-srv.quit:
	}
	return ps
}

// PeerCount returns the number of connected peers.
func (srv *Server) PeerCount() int {
	var count int
	select {
	case srv.peerOp <- func(ps map[discover.NodeID]*Peer) { count = len(ps) }:
		<-srv.peerOpDone
	case <-srv.quit:
	}
	return count
}

// AddPeer connects to the given node and maintains the connection until the
// server is shut down. If the connection fails for any reason, the server will
// attempt to reconnect the peer.
func (srv *Server) AddPeer(node *discover.Node) {
	//增加一个peer
	select {
	case srv.addstatic <- node:
	case <-srv.quit:
	}
}

// RemovePeer disconnects from the given node
func (srv *Server) RemovePeer(node *discover.Node) {
	select {
	case srv.removestatic <- node:
	case <-srv.quit:
	}
}

// SubscribePeers subscribes the given channel to peer events
func (srv *Server) SubscribeEvents(ch chan *PeerEvent) event.Subscription {
	return srv.peerFeed.Subscribe(ch)
}

// Self returns the local node's endpoint information.
func (srv *Server) Self() *discover.Node {
	//返回我自己的信息
	srv.lock.Lock()
	defer srv.lock.Unlock()

	if !srv.running {
		return &discover.Node{IP: net.ParseIP("0.0.0.0")}
	}
	return srv.makeSelf(srv.listener, srv.ntab)
}

//O
func (srv *Server) makeSelf(listener net.Listener, ntab discoverTable) *discover.Node {
	// If the server's not running, return an empty node.
	// If the node is running but discovery is off, manually assemble the node infos.
	if ntab == nil {
		// Inbound connections disabled, use zero address.
		if listener == nil {
			return &discover.Node{IP: net.ParseIP("0.0.0.0"), ID: discover.PubkeyID(&srv.PrivateKey.PublicKey)}
		}
		// Otherwise inject the listener address too
		addr := listener.Addr().(*net.TCPAddr)
		return &discover.Node{
			ID:  discover.PubkeyID(&srv.PrivateKey.PublicKey),
			IP:  addr.IP,
			TCP: uint16(addr.Port),
		}
	}
	// Otherwise return the discovery node.
	return ntab.Self()
}

// Stop terminates the server and all active peer connections.
// It blocks until all active connections have been closed.
func (srv *Server) Stop() {
	srv.lock.Lock()
	defer srv.lock.Unlock()
	if !srv.running {
		return
	}
	srv.running = false
	if srv.listener != nil {
		// this unblocks listener Accept
		srv.listener.Close()
	}
	close(srv.quit)
	srv.loopWG.Wait()
}

// sharedUDPConn implements a shared connection. Write sends messages to the underlying connection while read returns
// messages that were found unprocessable and sent to the unhandled channel by the primary listener.
type sharedUDPConn struct {
	*net.UDPConn
	unhandled chan discover.ReadPacket
}

// ReadFromUDP implements discv5.conn
func (s *sharedUDPConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	packet, ok := <-s.unhandled
	if !ok {
		return 0, nil, fmt.Errorf("Connection was closed")
	}
	l := len(packet.Data)
	if l > len(b) {
		l = len(b)
	}
	copy(b[:l], packet.Data[:l])
	return l, packet.Addr, nil
}

// Close implements discv5.conn
func (s *sharedUDPConn) Close() error {
	return nil
}

// Start starts running the server.
// Servers can not be re-used after stopping.
func (srv *Server) Start() (err error) {
	//startNode-> stack.Start() 里面会调用这里启动p2p服务
	srv.lock.Lock() //加锁
	defer srv.lock.Unlock()
	if srv.running {
		return errors.New("server already running")
	}
	srv.running = true
	srv.log = srv.Config.Logger
	if srv.log == nil {
		srv.log = log.New()
	}
	srv.log.Info("Starting P2P networking")

	// static fields
	if srv.PrivateKey == nil {
		return fmt.Errorf("Server.PrivateKey must be set to a non-nil key")
	}
	if srv.newTransport == nil {// 钩子
		//这是以太坊的基于TCP之上的加密握手协议RLPx , UDP不需要
		srv.newTransport = newRLPX
	}
	if srv.Dialer == nil {
		srv.Dialer = TCPDialer{&net.Dialer{Timeout: defaultDialTimeout}}
	}

	//下面是一堆用于管理peer的管道, 接下来会监听他们
	srv.quit = make(chan struct{})
	srv.addpeer = make(chan *conn) //增加peer
	srv.delpeer = make(chan peerDrop)
	srv.posthandshake = make(chan *conn)
	srv.addstatic = make(chan *discover.Node)
	srv.removestatic = make(chan *discover.Node)
	srv.peerOp = make(chan peerOpFunc)
	srv.peerOpDone = make(chan struct{})

	var (
		conn      *net.UDPConn
		sconn     *sharedUDPConn
		realaddr  *net.UDPAddr
		unhandled chan discover.ReadPacket
	)

	if !srv.NoDiscovery || srv.DiscoveryV5 {
		//网络发现服务, 用UDP协议 ， 这里的目的是生成一个udp协议地址字段, 设置一个UDP listen监听句柄
		addr, err := net.ResolveUDPAddr("udp", srv.ListenAddr)
		if err != nil {
			return err
		}
		//下面这个会将这个udp连接设置为listen状态
		conn, err = net.ListenUDP("udp", addr)
		if err != nil {
			return err
		}
		realaddr = conn.LocalAddr().(*net.UDPAddr)
		if srv.NAT != nil {
			//如果配置了NAT，那么需要做网络映射，映射到新的外网地址
			if !realaddr.IP.IsLoopback() {
				go nat.Map(srv.NAT, srv.quit, "udp", realaddr.Port, realaddr.Port, "ethereum discovery")
			}
			// TODO: react to external IP changes over time.
			if ext, err := srv.NAT.ExternalIP(); err == nil {
				realaddr = &net.UDPAddr{IP: ext, Port: realaddr.Port}
			}
		}
	}

	if !srv.NoDiscovery && srv.DiscoveryV5 {
		//新版服务发现协议 使用新的方式
		unhandled = make(chan discover.ReadPacket, 100)
		sconn = &sharedUDPConn{conn, unhandled}
	}

	// node table
	if !srv.NoDiscovery {
		cfg := discover.Config{
			PrivateKey:   srv.PrivateKey,
			AnnounceAddr: realaddr,
			NodeDBPath:   srv.NodeDatabase,
			NetRestrict:  srv.NetRestrict,
			Bootnodes:    srv.BootstrapNodes, //初始启动peer节点
			Unhandled:    unhandled,
		}
		//开启后台协程进行UDP监听, 如果有新的数据包到来，会通知到 unhandled（如果用的是DiscoveryV5） 上面
		//discover包会使用conn这个UDP 监听链接，不断读取数据包进行处理
		//同时，discover会自己维护cfg上面设置的Bootnodes 初始连接节点，
		//进而进行p2p扩展，不断发送findnode包询问最近的临接节点，并加入到自己的Table.buckets列表中
		//ntab 是discover.udp结构，同时也匿名继承了discover.Table类
		ntab, err := discover.ListenUDP(conn, cfg)
		if err != nil {
			return err
		}
		srv.ntab = ntab
	}

	if srv.DiscoveryV5 {
		//--v5disc 参数控制，默认关闭
		var (
			ntab *discv5.Network
			err  error
		)
		if sconn != nil {
			ntab, err = discv5.ListenUDP(srv.PrivateKey, sconn, realaddr, "", srv.NetRestrict) //srv.NodeDatabase)
		} else {
			ntab, err = discv5.ListenUDP(srv.PrivateKey, conn, realaddr, "", srv.NetRestrict) //srv.NodeDatabase)
		}
		if err != nil {
			return err
		}
		//设置启动节点，至少需要一个节点才能连接上整个P2P网络
		if err := ntab.SetFallbackNodes(srv.BootstrapNodesV5); err != nil {
			return err
		}
		srv.DiscV5 = ntab
	}

	dynPeers := srv.maxDialedConns()
	//新建一个dialstate结构返回 , StaticNodes 会直接加到srv.static[]数组里面
	//dialer是用来接听到上面的一堆管道事件后，管理nodes列表的, 发送TCP连接的
	dialer := newDialState(srv.StaticNodes, srv.BootstrapNodes, srv.ntab, dynPeers, srv.NetRestrict)

	// handshake
	srv.ourHandshake = &protoHandshake{Version: baseProtocolVersion, Name: srv.Name, ID: discover.PubkeyID(&srv.PrivateKey.PublicKey)}
	for _, p := range srv.Protocols {
		srv.ourHandshake.Caps = append(srv.ourHandshake.Caps, p.cap())
	}
	// listen/dial
	if srv.ListenAddr != "" {
		//开始监听TCP请求, TCP端口是需要加密的，传输的信息比较敏感，所以有握手过程
		if err := srv.startListening(); err != nil {
			return err
		}
	}
	if srv.NoDial && srv.ListenAddr == "" {
		srv.log.Warn("P2P server will be useless, neither dialing nor listening")
	}

	srv.loopWG.Add(1)
	//在协程里面运行, 开始监听各个信号量，处理peer的增删改.
	//并且一开始会scheduleTasks尝试连接其他节点
	go srv.run(dialer)
	srv.running = true
	return nil
}

func (srv *Server) startListening() error {
	// Launch the TCP listener.
	//先创建一个TCP监听句柄, 然后创建listenLoop协程进行不断的监听请求，进行Accept，然后握手，建立安全连接
	listener, err := net.Listen("tcp", srv.ListenAddr)
	if err != nil {
		return err
	}
	laddr := listener.Addr().(*net.TCPAddr)
	srv.ListenAddr = laddr.String()
	srv.listener = listener
	srv.loopWG.Add(1)
	//进入监听协程监听请求
	go srv.listenLoop()

	//处理NAT网络
	// Map the TCP listening port if NAT is configured.
	if !laddr.IP.IsLoopback() && srv.NAT != nil {
		srv.loopWG.Add(1)
		go func() {
			nat.Map(srv.NAT, srv.quit, "tcp", laddr.Port, laddr.Port, "ethereum p2p")
			srv.loopWG.Done()
		}()
	}
	return nil
}

type dialer interface {
	newTasks(running int, peers map[discover.NodeID]*Peer, now time.Time) []task
	taskDone(task, time.Time)
	addStatic(*discover.Node)
	removeStatic(*discover.Node)
}

func (srv *Server) run(dialstate dialer) {
	//连接池管理协程，负责维护TCP连接列表
	//在协程里面运行, 开始监听各个信号量，处理peer的增删改
	defer srv.loopWG.Done()
	var (
		peers        = make(map[discover.NodeID]*Peer)
		inboundCount = 0
		trusted      = make(map[discover.NodeID]bool, len(srv.TrustedNodes))
		taskdone     = make(chan task, maxActiveDialTasks)
		//当前正在使用的链接
		runningTasks []task
		queuedTasks  []task // tasks that can't run yet
	)
	// Put trusted nodes into a map to speed up checks.
	// Trusted peers are loaded on startup and cannot be
	// modified while the server is running.
	//可信节点，配置的 由trusted-nodes.json设置
	for _, n := range srv.TrustedNodes {
		trusted[n.ID] = true
	}

	// removes t from runningTasks
	delTask := func(t task) {
		for i := range runningTasks {
			if runningTasks[i] == t {
				runningTasks = append(runningTasks[:i], runningTasks[i+1:]...)
				break
			}
		}
	}
	// starts until max number of active tasks is satisfied
	//用来跟参数数组代表的节点一个个创建协程简历连接
	startTasks := func(ts []task) (rest []task) {
		i := 0
		//最多可以建立maxActiveDialTasks 个链接
		for ; len(runningTasks) < maxActiveDialTasks && i < len(ts); i++ {
			t := ts[i]
			srv.log.Trace("New dial task", "task", t)
			go func() { t.Do(srv); taskdone <- t }()
			//当前正在使用的链接
			runningTasks = append(runningTasks, t)
		}
		return ts[i:]
	}
	//用来扫描服务发现的P2P节点，建立TCP连接, 这也是最重要的步骤了
	scheduleTasks := func() {
		// Start from queue first.
		// 先尝试用startTasks 调用 queuedTasks 列表，试图一个个建立链接，不过可能由于maxActiveDialTasks 的限制,默认16个
		//所以下面这行代码可以不断运行，直到为空
		queuedTasks = append(queuedTasks[:0], startTasks(queuedTasks)...)
		// Query dialer for new tasks and start as many as possible now.
		//如果已经建立的链接还不到16个，那么尝试从p2p discover  中找出更多节点来用
		if len(runningTasks) < maxActiveDialTasks {
			nt := dialstate.newTasks(len(runningTasks)+len(queuedTasks), peers, time.Now())
			queuedTasks = append(queuedTasks, startTasks(nt)...)
		}
	}

running:
	for {
		//不断尝试去建立P2P的TCP连接
		scheduleTasks()

		//下面开始监听各个管道的事件，来处理peer的增删改操作
		select {
		case <-srv.quit:
			// The server was stopped. Run the cleanup logic.
			break running
		case n := <-srv.addstatic:
			// This channel is used by AddPeer to add to the
			// ephemeral static peer list. Add it to the dialer,
			// it will keep the node connected.
			srv.log.Debug("Adding static node", "node", n)
			dialstate.addStatic(n)
		case n := <-srv.removestatic:
			// This channel is used by RemovePeer to send a
			// disconnect request to a peer and begin the
			// stop keeping the node connected
			srv.log.Debug("Removing static node", "node", n)
			dialstate.removeStatic(n)
			if p, ok := peers[n.ID]; ok {
				p.Disconnect(DiscRequested)
			}
		case op := <-srv.peerOp:
			// This channel is used by Peers and PeerCount.
			op(peers)
			srv.peerOpDone <- struct{}{}
		case t := <-taskdone:
			// A task got done. Tell dialstate about it so it
			// can update its state and remove it from the active
			// tasks list.
			srv.log.Trace("Dial task done", "task", t)
			dialstate.taskDone(t, time.Now())
			delTask(t)
		case c := <-srv.posthandshake:
			// A connection has passed the encryption handshake so
			// the remote identity is known (but hasn't been verified yet).
			if trusted[c.id] {
				// Ensure that the trusted flag is set before checking against MaxPeers.
				c.flags |= trustedConn
			}
			// TODO: track in-progress inbound node IDs (pre-Peer) to avoid dialing them.
			select {
			case c.cont <- srv.encHandshakeChecks(peers, inboundCount, c):
			case <-srv.quit:
				break running
			}
		case c := <-srv.addpeer://握手完成，进行peer的增加和启动监听事件。
			// At this point the connection is past the protocol handshake.
			// Its capabilities are known and the remote identity is verified.
			err := srv.protoHandshakeChecks(peers, inboundCount, c)
			if err == nil {
				// The handshakes are done and it passed all checks.
				//空跑的话就这两个协议，eth: {Name:eth Version:63 Length:17 Run:0xae30b0 NodeInfo:0xae3300 PeerInfo:0xae3360} {Name:eth Version:62 Length:8 Run:0xae30b0 NodeInfo:0xae3300 PeerInfo:0xae3360}
				p := newPeer(c, srv.Protocols) //创建一个peer结构。
				// If message events are enabled, pass the peerFeed
				// to the peer
				if srv.EnableMsgEvents {
					p.events = &srv.peerFeed
				}
				name := truncateName(c.name)
				srv.log.Debug("Adding p2p peer", "name", name, "addr", c.fd.RemoteAddr(), "peers", len(peers)+1)
				//创建协程 去处理，增加这个peer
				go srv.runPeer(p)
				peers[c.id] = p
				if p.Inbound() {
					inboundCount++
				}
			}
			// The dialer logic relies on the assumption that
			// dial tasks complete after the peer has been added or
			// discarded. Unblock the task last.
			select {
			case c.cont <- err:
			case <-srv.quit:
				break running
			}
		case pd := <-srv.delpeer:
			// A peer disconnected.
			d := common.PrettyDuration(mclock.Now() - pd.created)
			pd.log.Debug("Removing p2p peer", "duration", d, "peers", len(peers)-1, "req", pd.requested, "err", pd.err)
			delete(peers, pd.ID())
			if pd.Inbound() {
				inboundCount--
			}
		}
	}

	//退出，开始关闭各连接个
	srv.log.Trace("P2P networking is spinning down")

	// Terminate discovery. If there is a running lookup it will terminate soon.
	if srv.ntab != nil {
		srv.ntab.Close()
	}
	if srv.DiscV5 != nil {
		srv.DiscV5.Close()
	}
	// Disconnect all peers.
	for _, p := range peers {
		p.Disconnect(DiscQuitting)
	}
	// Wait for peers to shut down. Pending connections and tasks are
	// not handled here and will terminate soon-ish because srv.quit
	// is closed.
	for len(peers) > 0 {
		p := <-srv.delpeer
		p.log.Trace("<-delpeer (spindown)", "remainingTasks", len(runningTasks))
		delete(peers, p.ID())
	}
}

func (srv *Server) protoHandshakeChecks(peers map[discover.NodeID]*Peer, inboundCount int, c *conn) error {
	// Drop connections with no matching protocols.
	if len(srv.Protocols) > 0 && countMatchingProtocols(srv.Protocols, c.caps) == 0 {
		return DiscUselessPeer
	}
	// Repeat the encryption handshake checks because the
	// peer set might have changed between the handshakes.
	return srv.encHandshakeChecks(peers, inboundCount, c)
}

func (srv *Server) encHandshakeChecks(peers map[discover.NodeID]*Peer, inboundCount int, c *conn) error {
	switch {
	case !c.is(trustedConn|staticDialedConn) && len(peers) >= srv.MaxPeers:
		return DiscTooManyPeers
	case !c.is(trustedConn) && c.is(inboundConn) && inboundCount >= srv.maxInboundConns():
		return DiscTooManyPeers
	case peers[c.id] != nil:
		return DiscAlreadyConnected
	case c.id == srv.Self().ID:
		return DiscSelf
	default:
		return nil
	}
}

func (srv *Server) maxInboundConns() int {
	return srv.MaxPeers - srv.maxDialedConns()
}

func (srv *Server) maxDialedConns() int {
	if srv.NoDiscovery || srv.NoDial {
		return 0
	}
	r := srv.DialRatio
	if r == 0 {
		r = defaultDialRatio
	}
	return srv.MaxPeers / r
}

type tempError interface {
	Temporary() bool
}

// listenLoop runs in its own goroutine and accepts
// inbound connections.
func (srv *Server) listenLoop() {
	//startListening 调用设置的.在新的协程不断坚挺新连接进来
	defer srv.loopWG.Done()
	srv.log.Info("RLPx listener up", "self", srv.makeSelf(srv.listener, srv.ntab))

	tokens := defaultMaxPendingPeers
	if srv.MaxPendingPeers > 0 {
		tokens = srv.MaxPendingPeers
	}
	slots := make(chan struct{}, tokens)
	for i := 0; i < tokens; i++ {
		//先直接放入这么多个slot进去，稍后就一个个获取了，用来实现并发控制。
		//因为实际上的链家请求简历，是通过协程进行的，并非在本协程处理，所以用了管道的形式来控制并发
		slots <- struct{}{}
	}

	for {
		// Wait for a handshake slot before accepting.
		<-slots //并发控制

		var (
			fd  net.Conn
			err error
		)
		for {
			//接受链接, 检查是否有问题，没问题就break
			fd, err = srv.listener.Accept()
			if tempErr, ok := err.(tempError); ok && tempErr.Temporary() {
				srv.log.Debug("Temporary read error", "err", err)
				continue
			} else if err != nil {
				srv.log.Debug("Read error", "err", err)
				return
			}
			break
		}

		// Reject connections that do not match NetRestrict.
		if srv.NetRestrict != nil {
			if tcp, ok := fd.RemoteAddr().(*net.TCPAddr); ok && !srv.NetRestrict.Contains(tcp.IP) {
				srv.log.Debug("Rejected conn (not whitelisted in NetRestrict)", "addr", fd.RemoteAddr())
				fd.Close()
				slots <- struct{}{}
				continue
			}
		}

		fd = newMeteredConn(fd, true)
		srv.log.Trace("Accepted connection", "addr", fd.RemoteAddr())
		//创建协程去处理这个链接
		go func() {
			//TCP连接是加密的，所以需要进行两边的握手，互相交换公钥
			srv.SetupConn(fd, inboundConn, nil)
			slots <- struct{}{} //通知上面的 listenLoop 协程可以继续下一个并发了
		}()
	}
}

// SetupConn runs the handshakes and attempts to add the connection
// as a peer. It returns when the connection has been added as a peer
// or the handshakes have failed.
func (srv *Server) SetupConn(fd net.Conn, flags connFlag, dialDest *discover.Node) error {
	self := srv.Self()
	if self == nil {
		return errors.New("shutdown")
	}
	//newTransport 目前使用的是RLPx加密协议，处理函数是newRLPX， 所以对于网络的读写，都是使用rlpxFrameRW接口去完成的
	c := &conn{fd: fd, transport: srv.newTransport(fd), flags: flags, cont: make(chan error)}
	err := srv.setupConn(c, flags, dialDest)
	if err != nil {
		c.close(err)
		srv.log.Trace("Setting up connection failed", "id", c.id, "err", err)
	}
	return err
}

func (srv *Server) setupConn(c *conn, flags connFlag, dialDest *discover.Node) error {
	//进行一个TCP协议上的握手
	// Prevent leftover pending conns from entering the handshake.
	srv.lock.Lock()
	running := srv.running
	srv.lock.Unlock()
	if !running {
		return errServerStopped
	}
	// Run the encryption handshake.
	var err error
	if c.id, err = c.doEncHandshake(srv.PrivateKey, dialDest); err != nil {
		srv.log.Trace("Failed RLPx handshake", "addr", c.fd.RemoteAddr(), "conn", c.flags, "err", err)
		return err
	}
	clog := srv.log.New("id", c.id, "addr", c.fd.RemoteAddr(), "conn", c.flags)
	// For dialed connections, check that the remote public key matches.
	if dialDest != nil && c.id != dialDest.ID {
		clog.Trace("Dialed identity mismatch", "want", c, dialDest.ID)
		return DiscUnexpectedIdentity
	}
	err = srv.checkpoint(c, srv.posthandshake)
	if err != nil {
		clog.Trace("Rejected peer before protocol handshake", "err", err)
		return err
	}
	// Run the protocol handshake
	phs, err := c.doProtoHandshake(srv.ourHandshake)
	if err != nil {
		clog.Trace("Failed proto handshake", "err", err)
		return err
	}
	if phs.ID != c.id {
		clog.Trace("Wrong devp2p handshake identity", "err", phs.ID)
		return DiscUnexpectedIdentity
	}
	c.caps, c.name = phs.Caps, phs.Name
	//将connection放入srv.addpeer中，并等待在c.cont上面，loop那边会触发cont的
	err = srv.checkpoint(c, srv.addpeer)
	if err != nil {
		clog.Trace("Rejected peer", "err", err)
		return err
	}
	// If the checks completed successfully, runPeer has now been
	// launched by run.
	clog.Trace("connection set up", "inbound", dialDest == nil)
	return nil
}

func truncateName(s string) string {
	if len(s) > 20 {
		return s[:20] + "..."
	}
	return s
}

// checkpoint sends the conn to run, which performs the
// post-handshake checks for the stage (posthandshake, addpeer).
func (srv *Server) checkpoint(c *conn, stage chan<- *conn) error {
	//通用的等待检查函数，用来等待某种事件的发生
	select {
	case stage <- c: //将conn 的连接结构，插入管道中，这个管道stage是专门传输conn指针的
	case <-srv.quit:
		return errServerStopped
	}
	select {
	case err := <-c.cont:
		return err
	case <-srv.quit:
		return errServerStopped
	}
}

// runPeer runs in its own goroutine for each peer.
// it waits until the Peer logic returns and removes
// the peer.
func (srv *Server) runPeer(p *Peer) {
	//跟一个peer连接建立完成后，调用这里来启动一个peer的维护，监听工作
	//go srv.runPeer(p)协程调用
	if srv.newPeerHook != nil {
		srv.newPeerHook(p)
	}

	// broadcast peer add
	//广播给别人
	srv.peerFeed.Send(&PeerEvent{
		Type: PeerEventTypeAdd,
		Peer: p.ID(),
	})

	// run the protocol
	//真正的peer处理函数，启动，开始进行消息读取，以及协议方面的处理，通知对应的协议层，增加了一个连接了
	remoteRequested, err := p.run()

	// broadcast peer drop
	srv.peerFeed.Send(&PeerEvent{
		Type:  PeerEventTypeDrop,
		Peer:  p.ID(),
		Error: err.Error(),
	})

	// Note: run waits for existing peers to be sent on srv.delpeer
	// before returning, so this send should not select on srv.quit.
	srv.delpeer <- peerDrop{p, err, remoteRequested}
}

// NodeInfo represents a short summary of the information known about the host.
type NodeInfo struct {
	ID    string `json:"id"`    // Unique node identifier (also the encryption key)
	Name  string `json:"name"`  // Name of the node, including client type, version, OS, custom data
	Enode string `json:"enode"` // Enode URL for adding this peer from remote peers
	IP    string `json:"ip"`    // IP address of the node
	Ports struct {
		Discovery int `json:"discovery"` // UDP listening port for discovery protocol
		Listener  int `json:"listener"`  // TCP listening port for RLPx
	} `json:"ports"`
	ListenAddr string                 `json:"listenAddr"`
	Protocols  map[string]interface{} `json:"protocols"`
}

// NodeInfo gathers and returns a collection of metadata known about the host.
func (srv *Server) NodeInfo() *NodeInfo {
	node := srv.Self()

	// Gather and assemble the generic node infos
	info := &NodeInfo{
		Name:       srv.Name,
		Enode:      node.String(),
		ID:         node.ID.String(),
		IP:         node.IP.String(),
		ListenAddr: srv.ListenAddr,
		Protocols:  make(map[string]interface{}),
	}
	info.Ports.Discovery = int(node.UDP)
	info.Ports.Listener = int(node.TCP)

	// Gather all the running protocol infos (only once per protocol type)
	for _, proto := range srv.Protocols {
		if _, ok := info.Protocols[proto.Name]; !ok {
			nodeInfo := interface{}("unknown")
			if query := proto.NodeInfo; query != nil {
				nodeInfo = proto.NodeInfo()
			}
			info.Protocols[proto.Name] = nodeInfo
		}
	}
	return info
}

// PeersInfo returns an array of metadata objects describing connected peers.
func (srv *Server) PeersInfo() []*PeerInfo {
	// Gather all the generic and sub-protocol specific infos
	infos := make([]*PeerInfo, 0, srv.PeerCount())
	for _, peer := range srv.Peers() {
		if peer != nil {
			infos = append(infos, peer.Info())
		}
	}
	// Sort the result array alphabetically by node identifier
	for i := 0; i < len(infos); i++ {
		for j := i + 1; j < len(infos); j++ {
			if infos[i].ID > infos[j].ID {
				infos[i], infos[j] = infos[j], infos[i]
			}
		}
	}
	return infos
}
