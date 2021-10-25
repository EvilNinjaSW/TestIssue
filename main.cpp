#include <winsock.h>
#include <windows.h>

#include <cstdlib>
#include <string>
#include <sstream>
#include <array>
#include <vector>
#include <map>
#include <thread>
#include <future>
#include <functional>
#include <atomic>
#include <cstdint>
#include <csignal>

#include "subprotocol.h"

#pragma comment(lib, "ws2_32.lib")

#define RECV_BUF 512
using tReceiveBlock = std::array<char, RECV_BUF>;

using tParticipant =
struct Participant
{
	std::string mLogin;
	std::string mPassword;
};
using tParticipantsDb = std::vector<tParticipant>;
using tSessionsDb = std::map<SOCKET, SessionInfo>;

class Protocol
{
private:
	std::stringstream mRawData;
	std::stringstream mExchangeData;
	bool mBeginExchange;
	bool mEndExchange;
	uint64_t mOpened;
	uint64_t mClosed;

public:
	Protocol() :
		mBeginExchange{ },
		mEndExchange{ true },
		mOpened{ },
		mClosed{ }
	{ }

	~Protocol() = default;

	bool parseVerifyAndGetAnswer(tReceiveBlock::const_pointer block,
		tReceiveBlock::size_type length,
		SessionInfo &sessionInfo,
		const std::shared_ptr<tParticipantsDb> &participantsDb,
		std::string &answer)
	{
		if (!length)
			return { };

		if (!mBeginExchange &&
			mEndExchange)
		{
			if (block[0] == '{')
			{
				mRawData.write(block, length);
				mBeginExchange = true;
				mEndExchange = false;

				if (analyse())
				{
					//ALLOW AND DENY logic here
					if (ProtocolIdMove::ExpectHello == sessionInfo.getTransision() &&
						ProtocolIdMove::ExpectHello == mGenericProtocol->getTransision() &&
						ProtocolId::Hello == mGenericProtocol->getProtocol())
					{
						answer = mGenericProtocol->createResponse();
						mGenericProtocol->switchStateUp();
						sessionInfo.switchStateUp();
						sessionInfo.saveData(*mGenericProtocol);
						return true;
					}
					else if (ProtocolIdMove::ExpectLogin == sessionInfo.getTransision() &&
						ProtocolIdMove::ExpectLogin == mGenericProtocol->getTransision() &&
						ProtocolId::Login == mGenericProtocol->getProtocol())
					{
						for (const auto &element : *participantsDb.get())
						{
							if (element.mLogin == mGenericProtocol->getLogin())
								if (element.mPassword == mGenericProtocol->getPassword())
								{
									answer = mGenericProtocol->createResponse();
									mGenericProtocol->switchStateUp();
									sessionInfo.switchStateUp();
									sessionInfo.saveData(*mGenericProtocol);
									return true;
								}
						}

						answer = mGenericProtocol->createResponse(false);
						return true;
					}
					else if (ProtocolIdMove::ExpectAfterAuth == sessionInfo.getTransision() &&
						ProtocolIdMove::ExpectAfterAuth == mGenericProtocol->getTransision())
					{
						if ((ProtocolId::Ping == mGenericProtocol->getProtocol() ||
							ProtocolId::Logout == mGenericProtocol->getProtocol()) &&
							mGenericProtocol->getSession() != sessionInfo.getSession())
						{
							answer = mGenericProtocol->createResponse(false);
							return true;
						}
						sessionInfo.setProtocol(mGenericProtocol->getProtocol());
						sessionInfo.saveData(*mGenericProtocol);
						answer = mGenericProtocol->createResponse();
						return true;
					}
					else
					{
						answer = sessionInfo.createResponse();
						return true;
					}

					return { };
				}
			}
			else
				return { };
		}

		if (mBeginExchange &&
			!mEndExchange)
		{
			mRawData.write(block, length);

			if (analyse())
			{
				answer = mGenericProtocol->createResponse();
				return { };
			}
		}

		return { };
	}

	bool lookupResponse(std::stringstream &&data, std::shared_ptr<SessionInfo> &responseInfo)
	{
		try
		{
			nlohmann::json json = nlohmann::json::parse(data.str());
			const auto command = json.at("command").get<std::string>();

			if (command == "HELLO")
			{
				responseInfo = std::make_shared<HelloOut>(std::move(data.str()));

				return true;
			}
			else if (command == "login")
			{
				responseInfo = std::make_shared<LoginOut>(std::move(data.str()));

				return true;
			}
			else if (command == "message")
			{
				responseInfo = std::make_shared<MessageOut>(std::move(data.str()));

				return true;
			}
			else if (command == "ping_reply")
			{
				responseInfo = std::make_shared<PingOut>(std::move(data.str()));

				return true;
			}
			else if (command == "logout_reply")
			{
				responseInfo = std::make_shared<LogoutOut>(std::move(data.str()));

				return true;
			}
		}
		catch (const std::exception &ex)
		{
			std::string info{ ex.what() };

			info.clear();
		}

		return { };
	}

private:
	Protocol(const Protocol &lhs) = delete;
	Protocol &operator =(const Protocol &lhs) = delete;
	Protocol(Protocol &&rhs) = delete;
	Protocol &operator =(Protocol &&rhs) = delete;

	std::unique_ptr<SessionInfo> mGenericProtocol;

	bool analyse(void)
	{
		auto data { mRawData.str() };
		bool result { true };

		std::for_each(std::cbegin(data), std::cend(data),
			[&](decltype (data)::const_reference value)
		{
			if (value == '{')
				++mOpened;
			else if (value == '}')
				++mClosed;
		});

		if (mOpened == mClosed)
		{
			mOpened = 0;
			mClosed = 0;
			mBeginExchange = false;
			mEndExchange = true;
			mRawData.str("");

			if (recognize(std::move(data)))
				result = true;
			else
				result = false;
		}

		return result;
	}

	bool recognize(std::string &&data)
	{
		try
		{
			nlohmann::json json = nlohmann::json::parse(data);
			const auto command = json.at("command").get<std::string>();

			if (command == "HELLO")
			{
				if (!mGenericProtocol)
				{
					mGenericProtocol = std::make_unique<Hello>(std::move(data));
				}
				else
					return { };

				return true;
			}
			else if (command == "login")
			{
				auto temporary = std::make_unique<LoginIn>(std::move(data));

				if (mGenericProtocol)
				{
					mGenericProtocol = std::move(temporary);
				}
				else
					return { };

				return true;
			}
			else if (command == "message")
			{
				auto temporary = std::make_unique<MessageIn>(std::move(data));

				if (mGenericProtocol)
				{
					mGenericProtocol = std::move(temporary);
				}
				else
					return { };

				return true;
			}
			else if (command == "ping")
			{
				auto temporary = std::make_unique<PingIn>(std::move(data));

				if (mGenericProtocol)
				{
					mGenericProtocol = std::move(temporary);
				}
				else
					return {  };

				return true;
			}
			else if (command == "logout")
			{
				auto temporary = std::make_unique<LogoutIn>(std::move(data));

				if (mGenericProtocol)
				{
					mGenericProtocol = std::move(temporary);
				}
				else
					return { };

				return true;
			}
		}
		catch (const std::exception &ex)
		{
			std::string info { ex.what() };

			info.clear();
		}

		return { };

	}
};

/*
	Приветствие. 
	Сообщение клиента:
	{
	    "id":1,
		"command":"HELLO"
	}

	Ответ сервера
	{
		"id":1,
		"command":"HELLO",
		"auth_method":"plain-text"
	}

	Авторизация
	Сообщение клиента:
	{
		"id":2,
		"command":"login",
		"login":"<login>",
		"password":"<password>",
	}

	Ответ сервера
	{
		"id":2,
		"command":"login",
		"status":"ok",
		"session":"<UUID сессии>"
	}
	или
	{
		"id":2,
		"command":"login",
		"status":"failed",
		"message":"сообщение об ошибке"
	}

	Отсылка сообщения
	Сообщение клиента:
	{
	    "id":2,
		"command":"message",
		"body":"<тело сообщения>",
		"session":"<UUID сессии>"
	}

	Ответ сервера
	{
	    "id":2,
		"command":"message_reply",
		"status":"ok",
		"client_id":"<id сообщения клиента>"
	}
	или (в случае если клиент не авторизован)
	{
		"id":2,
		"command":"message_reply",
		"status":"failed",
		"message":"сообщение об ошибке"
	}
	Отсылка сообщения с серверва
	Сообщение клиента:
	{
		"id":2,
		"command":"message",
		"body":"<тело сообщения>",
		"sender_login":"<login>",
		"session":"<UUID сессии>"
	}

	Ответ клиента
	{
		"id":2,
		"command":"message_reply",
		"status":"ok",
		"client_id":"<id сообщения>"
	}
	или (в случае если клиент не авторизован)
	{
		"id":2,
		"command":"message_reply",
		"status":"failed",
		"message":"сообщение об ошибке"
	}

	Проверка соединения
	Сообщение клиента:
	{
		"id":2,
		"command":"ping",
		"session":"<UUID сессии>"
	}

	Ответ сервера
	{
		"id":2,
		"command":"ping_reply",
		"status":"ok",
	}
	или (в случае если клиент не авторизован)
	{
		"id":2,
		"command":"ping_reply",
		"status":"failed",
		"message":"сообщение об ошибке"
	}

	Рассоединение
	Сообщение клиента:
	{
		"id":2,
		"command":"logout",
		"session":"<UUID сессии>"
	}
	Ответ сервера
	{
		"id":2,
		"command":"logout_reply",
		"status":"ok",
	}
*/

using tClientInfo =
struct ClientInfo
{
	SOCKET mSocket;
	int mLoginTimeout;
	std::string mData;
	SessionInfo mSessionInfo;
};

using tClientsId = std::map<int, tClientInfo>;

class ConnectionRecords
{
protected:
	tClientsId mClientsId;

public:
	ConnectionRecords() { }
	~ConnectionRecords() { }

	ConnectionRecords(const ConnectionRecords &lhs) = default;

	bool addRecord(SOCKET socket)
	{
		tClientInfo clientInfo { socket, 4 };

		if (std::crend(mClientsId) == mClientsId.crbegin())
		{
			mClientsId.try_emplace(0, std::move(clientInfo));
		}
		else
		{
			mClientsId.try_emplace(mClientsId.crbegin()->first + 1, std::move(clientInfo));
		}

		return true;
	}

	bool removeRecord(SOCKET socket)
	{
		for (auto it = mClientsId.cbegin(); it != mClientsId.cend();)
		{
			if (it->second.mSocket == socket)
			{
				it = mClientsId.erase(it);
				return true;
			}
			else
				++it;
		}

		return {};
	}

	tClientsId &getAllRecords(void)
	{
		return mClientsId;
	}

	tClientsId::value_type &getLastRecord(void)
	{
		return *mClientsId.rbegin();
	}

private:
	ConnectionRecords & operator =(const ConnectionRecords &lhs) = default;
	ConnectionRecords(ConnectionRecords &&rhs) = delete;
	ConnectionRecords &operator =(ConnectionRecords &&rhs) = delete;
};

class ConnectionInfo;
class Server;
class Client;

class ConnectionInfo
{
private:
#define SOCK_LIB_OK 0
	ConnectionRecords mConnectionRecords;
	std::recursive_mutex mRecordsMutex;

	bool mIsInited;
	SOCKET mMainSocket;
	sockaddr_in mSockAddr;
	uint64_t mCurrentConnectionId;

	bool initLib(void)
	{
		WSADATA wsaData{};

		return SOCK_LIB_OK == WSAStartup(MAKEWORD(2, 2), &wsaData);
	}

	bool cleanupLib(void)
	{
		return SOCK_LIB_OK == WSACleanup();
	}

	bool createMainSocket(void)
	{
		if (mIsInited)
			return INVALID_SOCKET != (mMainSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));

		return {};
	}

	bool setupMainSocket(void)
	{
		mSockAddr.sin_family = AF_INET;
		mSockAddr.sin_port = htons(12345);
		mSockAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

		if (mIsInited &&
			INVALID_SOCKET != mMainSocket)
			return SOCKET_ERROR != bind(mMainSocket, reinterpret_cast<const sockaddr *>(&mSockAddr), sizeof mSockAddr) &&
			SOCKET_ERROR != listen(mMainSocket, SOMAXCONN);

		return {};
	}

public:
	ConnectionInfo() :
		mIsInited { initLib() },
		mMainSocket { INVALID_SOCKET },
		mSockAddr { },
		mCurrentConnectionId { }
	{ }

	~ConnectionInfo()
	{
		cleanupLib();
	}

	auto isInited(void) const { return mIsInited; }

	auto getNextConnectionId(void) { return ++mCurrentConnectionId; }

	template <typename EndPoint, typename Param>
	bool add(Param param)
	{
		if constexpr (std::is_same<EndPoint, Server>::value)
		{
			int len{ sizeof mSockAddr };

			if (INVALID_SOCKET != (param = accept(mMainSocket, reinterpret_cast<sockaddr *>(&mSockAddr), &len)))
			{
				std::lock_guard<decltype (mRecordsMutex)> lock(mRecordsMutex/*.lock()*/);

				if (mConnectionRecords.addRecord(param))
				{
					return true;
				}
				else
				{
					//todo
				}
			}

			return {};
		}
		else if (std::is_same_v<EndPoint, Client>)
		{
			int len{ sizeof mSockAddr };

			mSockAddr.sin_family = AF_INET;
			mSockAddr.sin_port = htons(12345);
			mSockAddr.sin_addr.s_addr = inet_addr(param.data());

			if (INVALID_SOCKET != connect(mMainSocket, reinterpret_cast<sockaddr *>(&mSockAddr), len))
			{
				if (mConnectionRecords.addRecord(mMainSocket))
					return true;
				else
					removeConnection();
			}

			return {};
		}
		else
		{
			static_assert(std::is_same_v<EndPoint, Server> ||
				std::is_same_v<EndPoint, Client>);
		}
	}

	template <typename EndPoint, typename Param>
	bool remove(Param param)
	{
		std::lock_guard<decltype (mRecordsMutex)> lock(mRecordsMutex);

		if (removeConnection(param))
		{
			mConnectionRecords.removeRecord(param);
			return true;
		}

		return { };
	}

	template <typename EndPoint>
	bool store(SOCKET socket,
		tReceiveBlock::const_pointer block,
		tReceiveBlock::size_type length)
	{
		std::lock_guard<decltype (mRecordsMutex)> lock(mRecordsMutex);

		auto &records { mConnectionRecords.getAllRecords() };

		if (auto found = records.find(socket);
			std::end() != found)
		{
			found->second.data.push_back({ std::cbegin(block), std::cend(block) });
				//emplace_back();
		}

		return { };
	}

	bool removeConnection(void)
	{
		auto isComplete { shutdown(mMainSocket, 2/*SD_BOTH*/) };

		if (isComplete != INVALID_SOCKET)
		{
			mMainSocket = INVALID_SOCKET;
			return true;
		}

		return { };
	}

	bool removeConnection(SOCKET socket)
	{
		return (INVALID_SOCKET != shutdown(socket, 2/*SD_BOTH*/));
	}

	void clear(void)
	{
		if (mIsInited &&
			INVALID_SOCKET != mMainSocket)
		{
			std::lock_guard<decltype (mRecordsMutex)> lock(mRecordsMutex);

			closesocket(mMainSocket);
			mMainSocket = INVALID_SOCKET;

			while (!mConnectionRecords.getAllRecords().empty())
			{
				auto records = mConnectionRecords.getAllRecords();
				auto const socket = records.cbegin()->second.mSocket;

				mConnectionRecords.removeRecord(socket);
				removeConnection(socket);
				//closesocket(socket);
			}
		}
	}

	bool prepareServer(void)
	{
		createMainSocket();
		setupMainSocket();

		return true;
	}

	bool prepareClient(void)
	{
		createMainSocket();
		//setupMainSocket();

		return true;
	}

	bool read(SOCKET socket, tReceiveBlock::pointer block,
		tReceiveBlock::size_type &length)
	{
		if (const auto status = recv(socket, block, length, 0);
			-1 == status || !status)
			return { };
		else
		{
			length = status;
			return true;
		}
	}

	bool write(SOCKET socketInfo, tReceiveBlock::const_pointer data, tReceiveBlock::size_type length)
	{
		if (mIsInited)
			return SOCKET_ERROR != send(socketInfo/*mMainSocket*/, data, length, 0);

		return {};
	}

	ConnectionRecords &getConnectionRecords(void)
	{
		return mConnectionRecords;
	}

private:
	ConnectionInfo(const ConnectionInfo &lhs) = delete;
	ConnectionInfo &operator =(const ConnectionInfo &lhs) = delete;
	ConnectionInfo(ConnectionInfo &&rhs) = delete;
	ConnectionInfo &operator =(ConnectionInfo &&rhs) = delete;
};

class Server
{
private:
	std::function<bool(std::shared_ptr<tParticipantsDb> &)> mFnCreateDb;

protected:
	bool mIsStarted;
	std::atomic_bool mStop;
	std::thread mConnectionThread;
	Protocol mProtocol;
	std::function<bool (SOCKET, std::stringstream &&)> mFnRead;
	std::function<bool (uint64_t, SessionInfo &)> mFnConnect;
	std::function<bool (Protocol &)> mFnParseProtocol;
	ConnectionInfo mConnectionInfo;
	tSessionsDb mSessionsDb;
	std::shared_ptr<tParticipantsDb> mParicipantsDb;

	virtual SOCKET getDestination()
	{
		return { };
	}

public:
	explicit Server(decltype (mFnRead) fnRead,
		decltype (mFnConnect) fnConnect,
		decltype (mFnCreateDb) fnCreateDb = nullptr) :
		mIsStarted { },
		mStop { },
		mFnRead { fnRead },
		mFnConnect { fnConnect },
		mFnCreateDb { fnCreateDb }
	{ }

	virtual ~Server()
	{
		mConnectionInfo.clear();
		stop();
	}

	void setAddress(const std::string);
	std::string getAddress(void) const { return {}; }

	virtual bool start(void)
	{
		if (!mFnCreateDb(mParicipantsDb))
			return false;

		mConnectionInfo.prepareServer();

		if (!mIsStarted)
		{
			mConnectionThread = std::thread(Server::connectSite,
				std::cref(mStop),
				std::ref(mConnectionInfo),
				std::ref(mProtocol),
				std::ref(mSessionsDb),
				std::cref(mParicipantsDb),
				std::ref(mFnRead),
				std::ref(mFnConnect));
			return (mIsStarted = true);
		}

		return {};
	}

	virtual bool stop(void)
	{
		if (mIsStarted)
		{
			mStop.store(true);
			mConnectionInfo.removeConnection();
			mConnectionInfo.clear();
			mConnectionThread.join();
			return (mIsStarted = false);
		}

		return { };
	}

	bool write(SOCKET socket, std::stringstream &&data)
	{
		tReceiveBlock block;
		auto length{ data.str().length() };

		if (!mIsStarted ||
			!length)
			return {};

		for (decltype (length) i{}; i < length; i += block.size())
		{
			const auto currentLength{ length - i > block.size() ?
				block.size() :
				length - i };

			std::copy_n(data.str().cbegin() + i,
				currentLength,
				block.begin());

			if (auto destination = getDestination();
				!mConnectionInfo.write(0 == destination ?
					socket :
					destination,
					block.data(),
					currentLength))
				return {};
		}

		return true;
	}

	bool read(std::stringstream &data)
	{
		return { };
	}

private:
	Server(const Server &lhs) = delete;
	Server &operator =(const Server &lhs) = delete;
	Server(Server &&rhs) = delete;
	Server &operator =(Server &&rhs) = delete;

	static void timeoutLogin(decltype (mConnectionInfo) &connectionInfo,
		SOCKET socket)
	{
		std::this_thread::sleep_for(std::chrono::seconds(5));

		//connectionInfo.remove<Server, SOCKET>(socket);
	}

private:
	static void connectSite(const decltype (mStop) &stop,
		decltype (mConnectionInfo) &connectionInfo,
		decltype (mProtocol) &protocol,
		decltype (mSessionsDb) &sessionsDb,
		const decltype (mParicipantsDb) &participantsDb,
		decltype (mFnRead) &read,
		decltype (mFnConnect) &connectId)
	{
		while (!stop.load())
		{
			if (SOCKET readWriteSocket { INVALID_SOCKET };
				connectionInfo.add<Server, SOCKET &>(readWriteSocket))
			{
				SessionInfo session;

				if (const auto sessionNumber = connectionInfo.getNextConnectionId();
					connectId(sessionNumber, session))
				{
					sessionsDb.try_emplace(readWriteSocket, std::move(session));

					std::thread timeoutLoginTask{ timeoutLogin,
						std::ref(connectionInfo),
						readWriteSocket };
					std::thread readTask{ receiveTask<Server>,
						std::cref(stop),
						readWriteSocket,
						std::ref(connectionInfo),
						std::cref(participantsDb),
						std::ref(protocol),
						std::ref(read) };

					timeoutLoginTask.detach();
					readTask.detach();
				}
			}
		}
	}

	//#define RECV_BUF 512
protected:
	template <typename T>
	static void receiveTask(const decltype (mStop) &stop,
		SOCKET rwSocket,
		decltype (mConnectionInfo) &connectionInfo,
		const decltype (mParicipantsDb) &participantsDb,
		decltype (mProtocol) &protocol,
		decltype (mFnRead) &read)
	{
		while (!stop.load())
		{
			tReceiveBlock block;

			if (decltype (block.size()) length { block.size() };
				!connectionInfo.read(rwSocket, block.data(), length))
				break;
			else
			{
				std::stringstream data(std::string { block.data(), length });

				if constexpr (std::is_same_v<Server, T>)
				{
					auto &records { connectionInfo.getConnectionRecords() };
					tClientsId::key_type siteId { };

					for (auto &element : records.getAllRecords())
					{
						if (element.second.mSocket == rwSocket)
						{
							siteId = element.first;
							element.second.mData.append(block.data(), length);

							if (std::string answer;
								protocol.parseVerifyAndGetAnswer(element.second.mData.data(),
									element.second.mData.length(),
									std::ref(element.second.mSessionInfo),
									std::cref(participantsDb),
									answer))
							{
								if (read(rwSocket/*siteId*/, std::stringstream(answer)))
								{
									if (ProtocolId::Logout == element.second.mSessionInfo.getProtocol())
									{
										connectionInfo.remove<Server, SOCKET>(rwSocket);
										break;
									}
								}

								element.second.mData.clear();
							}
							break;
						}
					}
				}
				else if (std::is_same_v<Client, T>)
				{
					auto &records { connectionInfo.getConnectionRecords() };
					tClientsId::key_type siteId { };

					for (auto &element : records.getAllRecords())
					{
						if (element.second.mSocket == rwSocket)
						{
							siteId = element.first;
							element.second.mData.append(block.data(), length);

							if (read(0, std::stringstream(element.second.mData)))
							{
								Protocol response;
								std::shared_ptr<SessionInfo> responseInfo;

								response.lookupResponse(std::move(data), responseInfo);

								if (ProtocolId::Logout == responseInfo->getProtocol() &&
									"ok" == responseInfo->getStatus())
								{
									connectionInfo.remove<Client, SOCKET>(rwSocket);
									break;
								}
							}

							element.second.mData.clear();
							
							break;
						}
					}
					//if (read(rwSocket/*siteId*/, std::move(data)))
					//{
					//	auto &records { connectionInfo.getConnectionRecords() };
					//}
				}
				else
				{
					static_assert((std::is_same_v<Server, T> ||
						std::is_same_v<Client, T>));
				}
			}
		}
	}
};

class Client :
	public Server
{
private:
	ConnectionInfo mConnectionInfo;

	SOCKET getDestination(void) override
	{
		return mConnectionInfo.getConnectionRecords().getLastRecord().second.mSocket;
	}

public:
	Client(decltype (mFnRead) fnRead,
		decltype (mFnConnect) fnConnect):
		Server(fnRead,
			fnConnect)
	{ }

	~Client() override
	{ }

	bool start(void) override
	{
		mConnectionInfo.prepareClient();

		if (mConnectionInfo.add<Client, std::string>("127.0.0.1"))
		{
			SessionInfo session;

			if (mFnConnect(mConnectionInfo.getNextConnectionId(), session))
			{
				mConnectionThread = std::thread{ receiveTask<Client>,
					std::cref(mStop),
					mConnectionInfo.getConnectionRecords().getLastRecord().second.mSocket,
					std::ref(mConnectionInfo),
					std::cref(mParicipantsDb),
					std::ref(mProtocol),
					std::ref(mFnRead) };
			}

			mIsStarted = true;
		}

		return mIsStarted;
	}

	bool stop(void) override
	{
		if (mConnectionInfo.removeConnection())
		{
			mConnectionInfo.clear();

			if (mConnectionThread.joinable())
				mConnectionThread.join();

			mIsStarted = false;
			return true;
		}

		return {};
	}

private:
	Client(const Client &lhs) = delete;
	Client &operator =(const Client &lhs) = delete;
	Client(Client &&rhs) = delete;
	Client &operator =(Client &&rhs) = delete;
};

//
Server *pServer;
Client *pClient;
//

void __cdecl signal_handle(int sig_num)
{
	if (SIGINT == sig_num)
		exit(0);
}

bool createServerDb(std::shared_ptr<tParticipantsDb> &sessionsDb)
{
	tParticipantsDb simpleParticipantsDb{ { "test_login1", "test_password1" },
	{ "test_login2", "test_password2" },
	{ "test_login3", "test_password3" },
	{ "test_login4", "test_password4" },
	{ "test_login5", "test_password5" } };

	sessionsDb = std::make_shared<tParticipantsDb>(simpleParticipantsDb);

	return { true };
}

bool connectServer(uint64_t id, SessionInfo &sessionInfo)
{
	sessionInfo.initServerSession(id);
	sessionInfo.provideVitalData("plain-auth");

	return { true };
}

bool connectClient(uint64_t id, SessionInfo &sessionInfo)
{
	sessionInfo.clientAuth(id, "test_name", "test_password");

	return { true };
}

bool readServer(SOCKET socket, std::stringstream &&data)
{
	/*static Protocol protocol;
	std::string answer;

	if (protocol.parseVerifyAndGetAnswer(data.str().data(), data.str().length(), answer))
	*/	return pServer->write(socket, std::move(data));

	return { true };
}

bool readClient(SOCKET socket, std::stringstream &&data)
{
	Protocol response;
	std::shared_ptr<SessionInfo> responseInfo;

	if (response.lookupResponse(std::move(data), responseInfo))
	{
		switch (responseInfo->getProtocol())
		{
		case ProtocolId::Hello:
		{
			std::stringstream nextStep;

			//nextStep << u8R"({"id":2,"command":"login","login":"MyName","password":"12345678"})";
			nextStep << u8R"({"id":2,"command":"login","login":"test_login3","password":"test_password3"})";
			pClient->write(0, std::move(nextStep));
		}
			break;
		case ProtocolId::Login:
		{
			std::stringstream nextStep;

			//nextStep << u8R"({"id":2,"command":"login","login":"MyName","password":"12345678"})";
			//nextStep << u8R"({ "id":2, "command":"logout", "session":"<UUID сессии>"})";
			nextStep << u8R"({ "id":2, "command":"ping", "session":"<UUID сессии>" })";
			pClient->write(0, std::move(nextStep));
		}
			break;
		case ProtocolId::Message:
			break;
		case ProtocolId::Ping:
			break;
		case ProtocolId::Logout:
			break;
		case ProtocolId::None:
		default:
			return { };
		}
	}

	return true;
}

void clientTestThread(int relation)
{
	//std::this_thread::sleep_for(std::chrono::seconds(5 + relation));

	auto fnRead = [&](std::stringstream &) -> bool
	{
		return { };
	};

	std::function<bool(uint64_t, SessionInfo &)> fnClientConnect { connectClient };
	std::function<bool (SOCKET, std::stringstream &&)> fnRead1 { readClient };

	Client *client = new Client(fnRead1,
		fnClientConnect);
	pClient = client;
	std::stringstream data[5];

	data[0] << u8R"raw({ "id": 1, "command" : "HELLO" })raw";

	data[1] << u8R"raw({
		"id":2,
		"command":"login",
		"login":"<login>",
		"password":"<password>"
	})raw";
	data[2] << u8R"raw({
		"id":2,
		"command":"message",
		"body":"<тело сообщения>",
		"session":"<UUID сессии>"
	})raw";
	data[3] << u8R"raw({
		"id":2,
		"command":"ping",
		"session":"<UUID сессии>"
	})raw";
	data[4] << u8R"raw({
		"id":2,
		"command":"logout",
		"session":"<UUID сессии>"
	})raw";

	client->start();
	std::this_thread::sleep_for(std::chrono::seconds(1));
	client->write(0, std::move(data[0]));
	//std::this_thread::sleep_for(std::chrono::seconds(5));
	//client->stop();
}

int main(int argc, char **argv)
{
	std::stringstream ss;

	ss << "Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.";

	signal(SIGINT, signal_handle);
	std::function<bool (uint64_t, SessionInfo &)> fnClientConnect { connectServer };
	std::function<bool (SOCKET, std::stringstream &&)> fnClientRead { readServer };
	std::function<bool (std::shared_ptr<tParticipantsDb> &)> fnCreateServerDb { createServerDb };
	Server server(fnClientRead, fnClientConnect, fnCreateServerDb);

	//
	pServer = &server;
	//

	server.start();
	//server.write(std::move(ss));

	std::thread testThreads[1]{ std::thread(clientTestThread, 0),
		/*std::thread(clientTestThread, 1),
		std::thread(clientTestThread, 2),
		std::thread(clientTestThread, 3),
		std::thread(clientTestThread, 4)*/ };

	std::this_thread::sleep_for(std::chrono::seconds(2));
	Sleep(-1);
	server.stop();

	for (auto &every : testThreads)
		every.join();

	return EXIT_SUCCESS;
}