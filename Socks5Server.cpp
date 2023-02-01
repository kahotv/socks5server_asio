#include <iostream>
#include <memory>
#include <optional>
#include <asio.hpp>
#include <coroutine>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/experimental/channel.hpp>
using std::move;

using asio::error_code;
using asio::ip::address;
using asio::ip::address_v4;
using asio::ip::address_v6;
using asio::ip::tcp;
using asio::ip::udp;
using asio::ip::address;
using asio::ip::port_type;
using asio::io_context;
using asio::awaitable;
using asio::steady_timer;
using asio::buffer;
using asio::co_spawn;
using asio::detached;
using asio::use_awaitable;
namespace this_coro = asio::this_coro;

using namespace asio::experimental::awaitable_operators;

enum class socks5Method : uint8_t
{
	NoAuth = 0,
	Gssapi = 1,
	UserPass = 2,
	Error = 0xFF
};

enum class socks5Cmd : uint8_t
{
	Connect = 1,
	Bind = 2,
	UdpAssociate = 3
};

enum class socks5AddrType : uint8_t
{
	IPv4 = 1,
	DomainName = 3,
	IPv6 = 4
};

void socks5_methods_show(uint8_t* methods, int num)
{
	for (int i = 0; i < num; i++)
	{
		uint8_t method = methods[i];

		switch (method)
		{
		case (int)socks5Method::NoAuth:
			printf("method[%d] = %d | 不需要身份验证\n", i, method);
			break;
		case (int)socks5Method::Gssapi:
			printf("method[%d] = %d | GSSAPI\n", i, method);
			break;
		case (int)socks5Method::UserPass:
			printf("method[%d] = %d | 用户密码认证\n", i, method);
			break;
		default:
			if (method >= 3 && method <= 0x7F)
				printf("method[%d] = %d | 未知的IANA方法\n", i, method);
			else
				printf("method[%d] = %d | 未知的Private方法\n", i, method);
			break;
		}
	}
}
bool socks5_methods_select(uint8_t* methods, int num, socks5Method method)
{
	for (int i = 0; i < num; i++)
	{
		if (methods[i] == (uint8_t)method)
			return true;
	}
	return false;
}

awaitable<void> replaySelectMethod(tcp::socket& sock, uint8_t method)
{
	uint8_t buf[2] = { 5,method };

	co_await asio::async_write(sock, buffer(buf), use_awaitable);
}

awaitable<void> socks5_auth_replay(tcp::socket& sock, bool succ)
{
	uint8_t buf[2] = { 1,(uint8_t)(succ ? 0 : 1) };
	co_await asio::async_write(sock, buffer(buf), use_awaitable);
}
awaitable<bool> socks5_auth(tcp::socket& sock)
{
	auto ctx = co_await this_coro::executor;
	size_t ulen = 0, plen = 0;
	uint8_t buf[0x100];

	std::string uname, passwd;

	//版本号
	co_await asio::async_read(sock, buffer(buf,1), use_awaitable);
	if (buf[0] != 0x01)
		co_return false;

	//账号
	co_await asio::async_read(sock, buffer(buf, 1), use_awaitable);
	ulen = buf[0];
	co_await asio::async_read(sock, buffer(buf, ulen), use_awaitable);
	uname.assign((const char*)buf, 0, ulen);

	//密码
	co_await asio::async_read(sock, buffer(buf, 1), use_awaitable);
	plen = buf[0];
	co_await asio::async_read(sock, buffer(buf, plen), use_awaitable);
	passwd.assign((const char*)buf, 0, plen);

	printf("[auth] unamelen: %d, passwdlen: %d\n", uname.length(), passwd.length());

	if (uname != "admin" || passwd != "123456")
	{
		printf("[auth] 失败: 账号密码错误\n");
		co_await socks5_auth_replay(sock, false);
		co_return false;
	}

	printf("[auth] 成功: 账号密码正确\n");
	co_await socks5_auth_replay(sock, true);

	co_return true;

}
awaitable<void> sock5_trans(tcp::socket& from, tcp::socket& to, size_t& size)
{
	auto ctx = co_await this_coro::executor;

	size_t n = 0;
	std::array<unsigned char, 4096> data;
	printf("[sock5_trans] begin %s:%d -> %s:%d\n",
		from.remote_endpoint().address().to_string().c_str(),
		from.remote_endpoint().port(),
		to.remote_endpoint().address().to_string().c_str(),
		to.remote_endpoint().port()
	);

	while (true)
	{
		n = co_await from.async_read_some(buffer(data), use_awaitable);

		//printf("[sock5_trans] recv %s:%d -> %s:%d | %d\n",
		//	from.remote_endpoint().address().to_string().c_str(),
		//	from.remote_endpoint().port(),
		//	to.remote_endpoint().address().to_string().c_str(),
		//	to.remote_endpoint().port(), n
		//);

		co_await asio::async_write(to, buffer(data, n), use_awaitable);

		size += n;

		//printf("[sock5_trans] sent %s:%d -> %s:%d | %d\n",
		//	from.remote_endpoint().address().to_string().c_str(),
		//	from.remote_endpoint().port(),
		//	to.remote_endpoint().address().to_string().c_str(),
		//	to.remote_endpoint().port(), n
		//);

	}
}

awaitable<void> socks5_request_replay(tcp::socket& sock, tcp::endpoint&& bind_ep, bool succ)
{
	int replay_len = 0;
	char buf[0x100];

	auto ctx = co_await this_coro::executor;

	buf[0] = 5;
	buf[1] = succ ? 0 : 1;
	buf[2] = 0;

	if (bind_ep.address().is_v4())
	{
		buf[3] = (uint8_t)socks5AddrType::IPv4;
		*(uint32_t*)&buf[4] = htonl(bind_ep.address().to_v4().to_uint());
		*(uint16_t*)&buf[4 + 4] = htons(bind_ep.port());
		replay_len = 4 + 4 + 2;
	}
	else// if(remote.address().is_v6())
	{
		buf[3] = (uint8_t)socks5AddrType::IPv6;
		auto bytes = bind_ep.address().to_v6().to_bytes();
		std::copy(bytes.data(), bytes.data() + bytes.size(), &buf[4]);
		*(uint16_t*)&buf[4 + bytes.size()] = htons(bind_ep.port());

		replay_len = 4 + 16 + 2;
	}

	co_await asio::async_write(sock, buffer(buf, replay_len), use_awaitable);
}
awaitable<void> socks5_request_replay(tcp::socket& sock, address bind_addr,port_type bind_port, bool succ)
{
	int replay_len = 0;
	char buf[0x100];

	auto ctx = co_await this_coro::executor;

	buf[0] = 5;
	buf[1] = succ ? 0 : 1;
	buf[2] = 0;

	if (bind_addr.is_v4())
	{
		buf[3] = (uint8_t)socks5AddrType::IPv4;
		*(uint32_t*)&buf[4] = htonl(bind_addr.to_v4().to_uint());
		*(uint16_t*)&buf[4 + 4] = htons(bind_port);
		replay_len = 4 + 4 + 2;
	}
	else// if(remote.address().is_v6())
	{
		buf[3] = (uint8_t)socks5AddrType::IPv6;
		auto bytes = bind_addr.to_v6().to_bytes();
		std::copy(bytes.data(), bytes.data() + bytes.size(), &buf[4]);
		*(uint16_t*)&buf[4 + bytes.size()] = htons(bind_port);

		replay_len = 4 + 16 + 2;
	}

	co_await asio::async_write(sock, buffer(buf, replay_len), use_awaitable);
}
awaitable<void> socks5_request_connect(tcp::socket sock, address addr,uint16_t port)
{
	auto ctx = co_await this_coro::executor;
	tcp::socket server(ctx);
	tcp::endpoint remote(addr, port);

	printf("[socks5_request_connect] connect %s:%d -> %s:%d\n",
		sock.remote_endpoint().address().to_string().c_str(),
		sock.remote_endpoint().port(),
		remote.address().to_string().c_str(),
		remote.port()
		);

	auto [e] = co_await server.async_connect(remote, asio::as_tuple(use_awaitable));
	
	if (e)
	{
		try
		{
			co_await socks5_request_replay(sock, server.local_endpoint(), false);
		}catch(...){}

		printf("[socks5_request_connect] connect %s:%d -> %s:%d 连接断开，总流量[%d],错误信息[%s]\n",
			sock.remote_endpoint().address().to_string().c_str(),
			sock.remote_endpoint().port(),
			remote.address().to_string().c_str(),
			remote.port(),
			0,
			e.message().c_str()
		);

		throw e;
	}

	printf("[socks5_request_connect] connect %s:%d -> %s:%d 成功，开始转发\n",
		sock.remote_endpoint().address().to_string().c_str(),
		sock.remote_endpoint().port(),
		remote.address().to_string().c_str(),
		remote.port()
	);

	size_t flow_up = 0, flow_down = 0;

	try
	{
		co_await socks5_request_replay(sock, server.local_endpoint(), true);
		co_await (sock5_trans(sock, server, flow_up) && sock5_trans(server, sock, flow_down));
	}
	catch (std::exception e)
	{
		printf("[socks5_request_connect] connect %s:%d -> %s:%d 连接断开，总流量[up: %d, down: %d],错误信息[%s]\n",
			sock.remote_endpoint().address().to_string().c_str(),
			sock.remote_endpoint().port(),
			remote.address().to_string().c_str(),
			remote.port(),
			flow_up, flow_down,
			e.what()
		);
		throw;
	}


}

awaitable<void> socks5_udpassociate_keepalive(tcp::socket& client)
{
	auto ctx = co_await this_coro::executor;

	char buf[0x10];
	while (true)
	{
		//一旦收到任何字节就中断，因为这不是socks5里的协议
		co_await client.async_read_some(buffer(buf), use_awaitable);
		throw asio::error::connection_aborted;
	}
}

awaitable< std::tuple<error_code, size_t, std::optional<udp::endpoint>>> socks5_udpassociate_handle_client(const char* buf, size_t len)
{
	/*
	  +----+------+------+----------+----------+----------+
      |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
      +----+------+------+----------+----------+----------+
      | 2  |  1   |  1   | Variable |    2     | Variable |
      +----+------+------+----------+----------+----------+
	*/

	auto ctx = co_await this_coro::executor;

	//2 + 1 + 1 + 2 =6
	if (len <= 6)
		co_return std::tuple(asio::error::invalid_argument, 0, std::nullopt);

	//RSV  Reserved X'0000'
	if (buf[0] != 0 && buf[1] != 0)
		co_return std::tuple(asio::error::invalid_argument, 0, std::nullopt);

	//FRAG    Current fragment number
	//暂不支持分片
	if (buf[2] != 0)
		co_return std::tuple(asio::error::operation_not_supported, 0, std::nullopt);

	size_t pos = 0;
	address addr;
	port_type port;
	address_v6::bytes_type addrv6;

	socks5AddrType atype = (socks5AddrType)buf[3];
	switch (atype)
	{
	case socks5AddrType::IPv4:
	{
		addr = asio::ip::make_address_v4(ntohl(*(uint32_t*)&buf[4]));
		port = ntohs(*(uint16_t*)&buf[8]);
		pos = 6 + 4;

		//printf("[socks5_udpassociate_handle_client] IPv4 : %s:%d\n", addr.to_string().c_str(), port);
		break;
	}

	case socks5AddrType::IPv6:
	{
		if (len <= 22)	//2 + 1 + 1 + 16 + 2 = 22
			co_return std::tuple(asio::error::invalid_argument, 0, std::nullopt);

		std::copy(buf + 4, buf + 4 + 16, addrv6.data());

		addr = asio::ip::make_address_v6(addrv6);
		port = ntohs(*(uint16_t*)&buf[4 + 16]);
		pos = 6 + 16;

		printf("[socks5_udpassociate_handle_client] IPv6 : %s:%d\n", addr.to_string().c_str(), port);
		break;
	}
	case socks5AddrType::DomainName:
	{
		uint8_t domain_len = buf[4];
		if (domain_len == 0)
		{
			printf("[socks5_udpassociate_handle_client] domain error: 域名长度为0\n");
			co_return std::tuple(asio::error::invalid_argument, 0, std::nullopt);
		}

		std::string domain(buf + 5, domain_len);
		std::string port_str = std::format("{}", ntohs(*(uint16_t*)(buf + 5 + domain_len)));

		printf("[socks5_udpassociate_handle_client] domain  %s:%s\n", domain.c_str(), port_str.c_str());
		//解析域名
		auto r = (co_await tcp::resolver(ctx).async_resolve(domain, port_str, use_awaitable));
		if (r.size() == 0)
		{
			printf("[socks5_udpassociate_handle_client] domain error: 解析域名失败 %s\n", domain.c_str());
			co_return std::tuple(asio::error::host_not_found, 0, std::nullopt);
		}

		addr = r->endpoint().address();
		port = r->endpoint().port();

		pos = 6 + 1 + domain_len;
		break;
		//return std::tuple(asio::error::operation_not_supported, 0, std::nullopt);
	}

	default:
		co_return std::tuple(asio::error::invalid_argument, 0, std::nullopt);
	}

	udp::endpoint ep(addr, port);

	//printf("[socks5_udpassociate_handle_client] up to : %s:%d\n", addr.to_string().c_str(), port);

	co_return std::tuple(asio::error_code{}, pos, std::make_optional(ep));
}
std::tuple<error_code,size_t> socks5_udpassociate_handle_server(size_t extra_size, char* buf, size_t len, size_t max, address cli_addr, port_type cli_port)
{
/*
  +----+------+------+----------+----------+----------+
  |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
  +----+------+------+----------+----------+----------+
  | 2  |  1   |  1   | Variable |    2     | Variable |
  +----+------+------+----------+----------+----------+
*/

	size_t head_size = 2 + 1 + 1 + (cli_addr.is_v4() ? 4 : 16) + 2;

	//超过包长度就丢掉
	if (head_size + len > max)
		return std::tuple(asio::error::no_memory, 0);

	char* head = buf - head_size;

	//RSV  Reserved X'0000'
	head[0] = 0;
	head[1] = 0;

	//FRAG    Current fragment number
	//暂不支持分片
	head[2] = 0;

	//ATYP
	if (cli_addr.is_v4())
	{
		head[3] = (uint8_t)socks5AddrType::IPv4;
		auto addrdata = cli_addr.to_v4().to_bytes();
		std::copy(addrdata.data(), addrdata.data() + addrdata.size(), head + 4);

		*(uint16_t*)(head + 4 + addrdata.size()) = htons(cli_port);
	}
	else 
	{
		head[3] = (uint8_t)socks5AddrType::IPv6;

		auto addrdata = cli_addr.to_v6().to_bytes();
		std::copy(addrdata.data(), addrdata.data() + addrdata.size(), head + 4);

		*(uint16_t*)(head + 4 + addrdata.size()) = htons(cli_port);
	}



	return std::tuple(error_code{}, head_size);
}


awaitable<void> sock5_udpassociate_trans(udp::socket& forward, address cli_addr, port_type cli_port, size_t& flow_up, size_t& flow_down)
{
	printf("[sock5_udpassociate_trans] from client [%s:%d]\n", cli_addr.to_string().c_str(), cli_port);


	char buf[0x2000];
	udp::endpoint ep_tmp;
	udp::endpoint ep_cli(cli_addr, cli_port);

	size_t extra_size = 0x20;	//必须大于22

	size_t recv_buf_size = sizeof(buf) - extra_size;
	char* recv_buf = buf + extra_size;

	while (true)
	{
		size_t n = co_await forward.async_receive_from(buffer(recv_buf, recv_buf_size), ep_tmp, use_awaitable);

		if (ep_cli.port() == 0)
		{
			//client地址为空，就把第一个udp包设定为客户端地址
			ep_cli = ep_tmp;
			printf("[sock5_udpassociate_trans] from client(update) [%s:%d]\n", ep_cli.address().to_string().c_str(), ep_cli.port());
		}

		//printf("[sock5_udpassociate_trans] from                [%s:%d] size: %d\n", ep_tmp.address().to_string().c_str(), ep_tmp.port(), n);

		if (ep_cli == ep_tmp)
		{

			//来自client，移除头后发给target
			auto [e,pos,ep_target] = co_await socks5_udpassociate_handle_client(recv_buf, n);
			if (!e)
			{
				//printf("[sock5_udpassociate_trans] up [%s:%d -> %s:%d]\n", ep_cli.address().to_string().c_str(), ep_cli.port(), ep_target.value().address().to_string().c_str(), ep_target.value().port());

				co_await forward.async_send_to(buffer(recv_buf + pos,n - pos), ep_target.value(), use_awaitable);

				flow_up += n - pos;
			}
			else 
			{
				printf("[sock5_udpassociate_trans] from client error [%s]\n", e.message().c_str());
			}
		}
		else 
		{
			//来自server，添加头后发给client
			auto [e,pos] = socks5_udpassociate_handle_server(extra_size, recv_buf, n, sizeof(buf), ep_tmp.address(), ep_tmp.port());

			//printf("[sock5_udpassociate_trans] down [%s:%d -> %s:%d]\n", ep_tmp.address().to_string().c_str(), ep_tmp.port(), ep_cli.address().to_string().c_str(), ep_cli.port());

			co_await forward.async_send_to(buffer(recv_buf - pos, n + pos), ep_cli, use_awaitable);

			flow_down += n;
		}
	}
}


awaitable<void> socks5_request_udpassociate(tcp::socket sock, address addr, port_type port)
{
	printf("[socks5_request_connect] udpassociate from %s:%d[%s:%d]\n",
		sock.remote_endpoint().address().to_string().c_str(),
		sock.remote_endpoint().port(),
		addr.to_string().c_str(),
		port
	);

	auto ctx = co_await this_coro::executor;

	udp::socket forward(ctx);

	asio::error_code ec;

	if (addr.is_v4())
	{
		forward.open(udp::v4());
		forward.bind({ udp::v4(), 0 }, ec);
	}
	else 
	{
		forward.open(udp::v6());
		forward.bind({ udp::v6(), 0 }, ec);
	}

	if(ec)
	{
		printf("[socks5_request_connect] udpassociate from %s:%d[%s:%d] 连接断开，总流量[%d],错误信息[%s]\n",
			sock.remote_endpoint().address().to_string().c_str(),
			sock.remote_endpoint().port(),
			addr.to_string().c_str(),
			port,
			0,
			ec.message().c_str()
		);
		//返回错误信息
		co_await socks5_request_replay(sock, forward.local_endpoint().address(), forward.local_endpoint().port(), false);
		co_return;
	}

	size_t flow_up = 0, flow_down = 0;

	try
	{
		//把绑定好的udp端口发回去
		co_await socks5_request_replay(sock, forward.local_endpoint().address(), forward.local_endpoint().port(), true);

		printf("[socks5_request_connect] udpassociate from %s:%d[%s:%d] | listen: %s:%d\n",
			sock.remote_endpoint().address().to_string().c_str(),
			sock.remote_endpoint().port(),
			addr.to_string().c_str(),
			port,
			forward.local_endpoint().address().to_string().c_str(),
			forward.local_endpoint().port()
		);

		//保持TCP连接当做心跳、UDP双向转发
		co_await(
			socks5_udpassociate_keepalive(sock) &&
			sock5_udpassociate_trans(forward, addr, port, flow_up, flow_down));
	}
	catch (std::exception e)
	{
		printf("[socks5_request_connect] udpassociate from %s:%d[%s:%d] 连接断开，总流量[up: %d, down: %d],错误信息[%s]\n",
			sock.remote_endpoint().address().to_string().c_str(),
			sock.remote_endpoint().port(),
			addr.to_string().c_str(),
			port,
			flow_up, flow_down,
			e.what()
		);

		throw;
	}

}

awaitable<void> socks5_request(tcp::socket& sock)
{
	auto ctx = co_await this_coro::executor;
	char buf[0x100];

	co_await asio::async_read(sock, buffer(buf, 4), use_awaitable);

	uint8_t ver = buf[0];
	socks5Cmd cmd = (socks5Cmd)buf[1];
	socks5AddrType addr_type = (socks5AddrType)buf[3];

	if (ver != 5)
	{
		throw asio::error::invalid_argument;
	}

	switch (cmd)
	{
	case socks5Cmd::Connect:
		break;
	case socks5Cmd::Bind:
		throw asio::error::operation_not_supported;
	case socks5Cmd::UdpAssociate:
		break;
	default:
		throw asio::error::invalid_argument;
		break;
	}

	address addr;
	port_type port;

	switch (addr_type)
	{
	case socks5AddrType::IPv4:
		if (cmd == socks5Cmd::Connect || cmd == socks5Cmd::UdpAssociate)
		{
			co_await asio::async_read(sock, buffer(buf, 4 + 2), use_awaitable);
			addr = asio::ip::make_address_v4(ntohl(*(uint32_t*)buf));
			port = ntohs( *(uint16_t*)&buf[4]);
		}
		break;
	case socks5AddrType::IPv6:
		if (cmd == socks5Cmd::Connect || cmd == socks5Cmd::UdpAssociate)
		{
			co_await asio::async_read(sock, buffer(buf, 16 + 2), use_awaitable);
			address_v6::bytes_type addrv6;
			std::copy(buf, buf + 16, addrv6.data());
			addr = asio::ip::make_address_v6(addrv6);
			port = ntohs(*(uint16_t*)&buf[16]);
		}
		break;
	case socks5AddrType::DomainName:
		if (cmd == socks5Cmd::Connect)
		{
			co_await asio::async_read(sock, buffer(buf, 1), use_awaitable);
			uint8_t domain_len = buf[0];
			if (domain_len == 0)
			{
				printf("[sock5_request] connect domain error: 域名长度为0\n");
				throw asio::error::invalid_argument;
			}

			co_await asio::async_read(sock, buffer(buf, domain_len), use_awaitable);
			std::string domain(buf, 0, domain_len);
			co_await asio::async_read(sock, buffer(buf, 2), use_awaitable);
			std::string port_str = std::format("{}", ntohs(*(uint16_t*)buf));

			printf("[sock5_request] connect domain  %s:%s\n", domain.c_str(), port_str.c_str());
			//解析域名
			auto r = (co_await tcp::resolver(ctx).async_resolve(domain, port_str, use_awaitable));
			if (r.size() == 0)
			{
				printf("[sock5_request] connect domain error: 解析域名失败 %s\n", domain.c_str());
				throw asio::error::host_not_found;
			}

			addr = r->endpoint().address();
			port = r->endpoint().port();
		}
		else if (cmd == socks5Cmd::UdpAssociate)
		{
			//此模式不支持域名
			throw asio::error::invalid_argument;
		}
		break;
	default:
		throw asio::error::invalid_argument;
		break;
	}


	if (cmd == socks5Cmd::Connect)
	{
		co_await socks5_request_connect(move(sock), addr, port);
	}
	else if (cmd == socks5Cmd::UdpAssociate)
	{
		co_await socks5_request_udpassociate(move(sock), addr, port);
	}
	else 
	{
		throw asio::error::invalid_argument;
	}
	
}
awaitable<void> socks5_handler(tcp::socket client)
{
	auto ctx = co_await this_coro::executor;
	size_t n = 0;

	uint8_t bufHead[0x100];

	//版本号
	co_await asio::async_read(client, buffer(bufHead, 1), use_awaitable);
	if (bufHead[0] != 5)
		co_return;

	//认证模式数组长度
	co_await asio::async_read(client, buffer(bufHead, 1), use_awaitable);
	int methodsNum = bufHead[0];
	if (methodsNum == 0)
		co_return;

	//选择认证模式
	co_await asio::async_read(client, buffer(bufHead, methodsNum), use_awaitable);
	socks5_methods_show(bufHead, methodsNum);
	if (socks5_methods_select(bufHead, methodsNum, socks5Method::UserPass))
	{
		printf("选择认证模式: [User/Pwd]\n");
		co_await replaySelectMethod(client, (uint8_t)socks5Method::UserPass);
		bool succ = co_await socks5_auth(client);
		if (!succ)
		{
			co_return;
		}
	}
	else if (socks5_methods_select(bufHead, methodsNum, socks5Method::NoAuth))
	{
		co_await replaySelectMethod(client, (uint8_t)socks5Method::NoAuth);
		printf("选择认证模式: [NoAuth]\n");
	}
	else 
	{
		co_await replaySelectMethod(client, (uint8_t)socks5Method::Error);
		printf("选择认证模式: [Error]\n");
		co_return;
	}


	co_await socks5_request(client);
}

awaitable<void> listener(uint16_t port)
{
	auto ctx = co_await this_coro::executor;
	tcp::endpoint addr(tcp::v4(), port);
	tcp::acceptor acceptor(ctx, addr);

	while (true)
	{
		tcp::socket sock = co_await acceptor.async_accept(use_awaitable);
		co_spawn(ctx, socks5_handler(move(sock)), detached);
	}
}

int main()
{
	io_context ctx;

	co_spawn(ctx, listener(11808), detached);

	//多线程转发数据
	std::thread([&]() {ctx.run(); }).detach();
	std::thread([&]() {ctx.run(); }).detach();
	std::thread([&]() {ctx.run(); }).detach();
	std::thread([&]() {ctx.run(); }).detach();
	std::thread([&]() {ctx.run(); }).detach();
	std::thread([&]() {ctx.run(); }).detach();
	
	system("pause");
}