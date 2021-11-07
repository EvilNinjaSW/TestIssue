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
#include <condition_variable>
#include <functional>
#include <atomic>
#include <cstdint>
#include <iostream>

#include "Session.h"

#pragma comment(lib, "ws2_32.lib")

//#define SEPARATE_CLIENT
#define TH_AMOUNT 5

std::thread gTestThreads[TH_AMOUNT];

std::mutex gClientReady[TH_AMOUNT];
std::mutex gServerReady;
std::condition_variable gWaitClient[TH_AMOUNT];
std::condition_variable gWaitServer;

#ifndef SEPARATE_CLIENT
//test purpose only
int gHello { };
int gLogin { };
int gMessage { };
int gPing { };
int gLogout { };
int gNone { };
#endif

std::wstring utf8_decode(const std::string &str)
{
    if (str.empty())
        return { };

    int size_needed { MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0) };
    std::wstring wstrTo(size_needed, 0);

    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::string utf8_encode(const std::wstring &wstr)
{
    if (wstr.empty())
        return { };

    int size_needed { WideCharToMultiByte(CP_ACP, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL) };
    std::string strTo(size_needed, 0);

    WideCharToMultiByte(CP_ACP, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

void waitForClientReady(int relation)
{
    std::unique_lock<std::mutex> lock(gClientReady[relation]);

    gWaitClient[relation].wait(lock/*, []()
    {
        return false;
    }*/);
}

void setClientReady(int relation)
{
    std::unique_lock<std::mutex> lock(gClientReady[relation]);

    gWaitClient[relation].notify_one();
}

void waitForServerReady(void)
{
    std::unique_lock<decltype (gServerReady)> lock(gServerReady);

    gWaitServer.wait(lock/*, []()
    {
        return false;
    }*/);
}

void setServerReady(void)
{
    std::unique_lock<decltype (gServerReady)> lock(gServerReady);

    gWaitServer.notify_one();
}

using tReceiveBlock = std::array<char, RECV_BUF>;
using tClientInfo =
struct ClientInfo
{
    ClientInfo() = default;
    ~ClientInfo() = default;

    ClientInfo(const ClientInfo &lhs) = delete;
    ClientInfo &operator =(const ClientInfo &lhs) = delete;
    ClientInfo(ClientInfo &&rhs) = default;
    ClientInfo &operator =(ClientInfo &&rhs) = delete;

    SOCKET mSocket;
    int mLoginTimeout;
    std::string mData;
    std::unique_ptr<SessionInfo> mSessionInfo;
    Protocol mProtocolState;
    int temp;
};

using tClientsId = std::map<int, tClientInfo>;

class ConnectionRecords
{
protected:
    tClientsId mClientsId;

public:
    ConnectionRecords()
    { }
    ~ConnectionRecords()
    { }

    ConnectionRecords(const ConnectionRecords &lhs) = default;

    bool addRecord(SOCKET socket,
                   std::unique_ptr<SessionInfo> &&sessionRequests,
                   int temp)
    {
        tClientInfo clientInfo { socket, 4, { }, std::move(sessionRequests), { }, temp };

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
        WSADATA wsaData {};

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
        mSockAddr {},
        mCurrentConnectionId {}
    { }

    ~ConnectionInfo()
    {
        cleanupLib();
    }

    auto isInited(void) const
    {
        return mIsInited;
    }

    auto getNextConnectionId(void)
    {
        return ++mCurrentConnectionId;
    }

    template <typename EndPoint, typename Param>
    bool add(Param param, int temp = 0)
    {
        if constexpr (std::is_same<EndPoint, Server>::value)
        {
            int len { sizeof mSockAddr };

            if (INVALID_SOCKET != (param = accept(mMainSocket, reinterpret_cast<sockaddr *>(&mSockAddr), &len)))
            {
                std::lock_guard<decltype (mRecordsMutex)> lock(mRecordsMutex);

                if (std::unique_ptr<SessionInfo> sessionRequests { std::make_unique<ServerSession>() };
                    mConnectionRecords.addRecord(param,
                    std::move(sessionRequests),
                    temp))
                {
                    return true;
                }
                else
                {
                    //todo
                }
            }

            return { };
        }
        else if (std::is_same_v<EndPoint, Client>)
        {
            int len { sizeof mSockAddr };

            mSockAddr.sin_family = AF_INET;
            mSockAddr.sin_port = htons(12345);
            mSockAddr.sin_addr.s_addr = inet_addr(param.data());

            if (INVALID_SOCKET != connect(mMainSocket, reinterpret_cast<sockaddr *>(&mSockAddr), len))
            {
                if (std::unique_ptr<SessionInfo> sessionRequests { std::make_unique<ClientSession>() };
                    mConnectionRecords.addRecord(mMainSocket,
                    std::move(sessionRequests),
                    temp))
                    return true;
                else
                    removeConnection();
            }

            return { };
        }
        else
        {
            static_assert(std::is_same_v<EndPoint, Server> ||
                          std::is_same_v<EndPoint, Client>);
        }
    }

    template <typename EndPoint, typename Param>
    bool propagateMessage(Param param, std::string &&message)
    {
        std::lock_guard<decltype (mRecordsMutex)> lock(mRecordsMutex);
        int isOk { };
        auto &records = mConnectionRecords.getAllRecords();

        if (records.size() <= 1)
            return false;

        isOk = 1;

        for (auto &client : records)
            if (param != client.second.mSocket)
                isOk &= write(client.second.mSocket, message.data(), message.length()) ? 1 : 0;

        return { isOk ? true : false };
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

        return {};
    }

    bool removeConnection(void)
    {
        auto isComplete { shutdown(mMainSocket, 2/*SD_BOTH*/) };

        if (isComplete != INVALID_SOCKET)
        {
            mMainSocket = INVALID_SOCKET;
            return true;
        }

        return {};
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
                auto &records = mConnectionRecords.getAllRecords();
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
        {
            return { };
        }
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

    tParticipant getCredentials(SOCKET socket)
    {
        for (const auto &record : mConnectionRecords.getAllRecords())
            if (record.second.mSocket == socket)
                return record.second.mSessionInfo->getCredentials();

        return { };
    }

private:
    ConnectionInfo(const ConnectionInfo &lhs) = delete;
    ConnectionInfo &operator =(const ConnectionInfo &lhs) = delete;
    ConnectionInfo(ConnectionInfo &&rhs) = delete;
    ConnectionInfo &operator =(ConnectionInfo &&rhs) = delete;
};

class Server
{
public:
    enum class ReplyResult
    {
        None,
        JustReply,
        ReplyAndPropagate,
        FinishSession,
        NeedMoreInfo
    };

    bool sendMessage(std::string login,
                     std::string message)
    {
        if (mIsStarted)
        {
            auto &records = mConnectionInfo.getConnectionRecords().getAllRecords();
            if (const auto &found = std::find_if(std::cbegin(records), std::cend(records),
                [&](std::decay<decltype (records)>::type::const_reference record)
            {
                const auto &credentials { record.second.mSessionInfo->getCredentials() };

                return credentials.mLogin == login;
            }
            );
                std::cend(records) != found)
            {
                return write(found->second.mSocket,
                             std::stringstream(dynamic_cast<ServerSession *>(found->second.mSessionInfo.get())->createSuperMessageRequest()));
            }
        }

        return { };
    }

private:
    std::function<bool(std::shared_ptr<tParticipantsDb> &)> mFnCreateDb;

protected:
    bool mIsStarted;
    std::atomic_bool mStop;
    std::thread mConnectionThread;
    std::function<std::tuple<Server::ReplyResult, std::string, std::string>
        (tClientInfo &,
         const std::shared_ptr<tParticipantsDb> &,
         tParticipantsDb &)> mFnCheckoutSession;
    std::function<bool(SOCKET, std::stringstream &&)> mFnRead;
    std::function<bool(uint64_t, SessionInfo &)> mFnConnect;
    ConnectionInfo mConnectionInfo;
    tSessionsDb mSessionsDb;
    std::shared_ptr<tParticipantsDb> mParicipantsDb;
    tParticipantsDb mParticipantsLoggedOn;

    virtual SOCKET getDestination()
    {
        return {};
    }

public:
    explicit Server(decltype (mFnRead) fnRead,
                    decltype (mFnConnect) fnConnect,
                    decltype (mFnCheckoutSession) fnCheckoutSession,
                    decltype (mFnCreateDb) fnCreateDb = nullptr) :
        mIsStarted {},
        mStop {},
        mFnRead { fnRead },
        mFnConnect { fnConnect },
        mFnCreateDb { fnCreateDb },
        mFnCheckoutSession { fnCheckoutSession }
    { }

    virtual ~Server()
    {
        mConnectionInfo.clear();
        stop();
    }

    void setAddress(const std::string);
    std::string getAddress(void) const
    {
        return {};
    }

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
                                            std::ref(mSessionsDb),
                                            std::cref(mParicipantsDb),
                                            std::ref(mParticipantsLoggedOn),
                                            std::ref(mFnRead),
                                            std::ref(mFnConnect),
                                            std::ref(mFnCheckoutSession));
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

        return {};
    }

    bool write(SOCKET socket, std::stringstream &&data)
    {
        tReceiveBlock block;
        auto length { data.str().length() };

        if (!mIsStarted ||
            !length)
            return {};

        for (decltype (length) i {}; i < length; i += block.size())
        {
            const auto currentLength { length - i > block.size() ?
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
        return {};
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
                            decltype (mSessionsDb) &sessionsDb,
                            const decltype (mParicipantsDb) &participantsDb,
                            decltype (mParticipantsLoggedOn) &participantsLoggedOn,
                            decltype (mFnRead) &read,
                            decltype (mFnConnect) &connectId,
                            decltype (mFnCheckoutSession) &checkoutSession)
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

                    std::thread timeoutLoginTask { timeoutLogin,
                        std::ref(connectionInfo),
                        readWriteSocket };
                    std::thread readTask { receiveTask<Server>,
                        std::cref(stop),
                        readWriteSocket,
                        std::ref(connectionInfo),
                        std::cref(participantsDb),
                        std::ref(participantsLoggedOn),
                        std::ref(read),
                        std::ref(checkoutSession) };

                    timeoutLoginTask.detach();
                    readTask.detach();
                }
            }
        }
    }

protected:
    template <typename T>
    static void receiveTask(const decltype (mStop) &stop,
                            SOCKET rwSocket,
                            decltype (mConnectionInfo) &connectionInfo,
                            const decltype (mParicipantsDb) &participantsDb,
                            decltype (mParticipantsLoggedOn) &participantsLoggedOn,
                            decltype (mFnRead) &read,
                            decltype (mFnCheckoutSession) &checkoutSession)
    {
        while (!stop.load())
        {
            tReceiveBlock block;

            if (decltype (block.size()) length { block.size() };
                !connectionInfo.read(rwSocket, block.data(), length))
            {
                auto participant = connectionInfo.getCredentials(rwSocket);

                if (const auto &element = std::remove(participantsLoggedOn.begin(), participantsLoggedOn.end(), participant);
                    std::end(participantsLoggedOn) != element)
                    participantsLoggedOn.erase(element);

                connectionInfo.remove<Server, SOCKET>(rwSocket);
                break;
            }
            else
            {
                if constexpr (std::is_same_v<Server, T>)
                {
                    for (auto &element : connectionInfo.getConnectionRecords().getAllRecords())
                    {
                        if (element.second.mSocket == rwSocket)
                        {
                            element.second.mData.append(block.data(), length);

                            if (auto replyResult = checkoutSession(element.second,
                                participantsDb,
                                participantsLoggedOn);
                                Server::ReplyResult::JustReply == std::get<0>(replyResult))
                            {
                                read(rwSocket, std::stringstream(std::get<1>(replyResult)));
                                break;
                            }
                            else if (Server::ReplyResult::ReplyAndPropagate == std::get<0>(replyResult))
                            {
                                read(rwSocket, std::stringstream(std::get<1>(replyResult)));
                                connectionInfo.propagateMessage<Server, SOCKET>(rwSocket, std::move(std::get<2>(replyResult)));
                                break;
                            }
                            else if (Server::ReplyResult::FinishSession == std::get<0>(replyResult))
                            {
                                read(rwSocket, std::stringstream(std::get<1>(replyResult)));
                                break;
                            }
                        }
                    }
                }
                else if (std::is_same_v<Client, T>)
                {
                    auto &records { connectionInfo.getConnectionRecords() };

                    for (auto &element : records.getAllRecords())
                    {
                        if (auto &clientInfo { element.second };
                            clientInfo.mSocket == rwSocket)
                        {
                            clientInfo.mData.append(block.data(), length);

                            for (; !clientInfo.mData.empty();)
                            {
                                auto temp = clientInfo.mData;
                                tParticipantsDb stub;

                                if (auto replyResult = checkoutSession(clientInfo,
                                    nullptr,
                                    stub);
                                    Server::ReplyResult::JustReply == std::get<0>(replyResult))
                                {
                                    read(clientInfo.temp,
                                         std::stringstream(temp.substr(0,
                                         temp.length() - clientInfo.mData.length())));
                                }
                                else if (Server::ReplyResult::FinishSession == std::get<0>(replyResult))
                                {
                                    read(clientInfo.temp, std::stringstream(temp.substr(0,
                                         temp.length() - clientInfo.mData.length())));
                                    connectionInfo.remove<Client, SOCKET>(rwSocket);
                                    break;
                                }
                                else if (Server::ReplyResult::NeedMoreInfo == std::get<0>(replyResult))
                                    break;
                            }

                            break;
                        }
                    }
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
public:
    bool sendHello(void)
    {
        if (mIsStarted)
        {
            auto &record = mConnectionInfo.getConnectionRecords().getLastRecord();

            return write(record.second.mSocket,
                         std::stringstream(dynamic_cast<ClientSession *>(record.second.mSessionInfo.get())->createHelloRequest()));
        }

        return { };
    }

    bool sendLogin(std::string login,
                   std::string password)
    {
        if (mIsStarted)
        {
            auto &record = mConnectionInfo.getConnectionRecords().getLastRecord();

            return write(record.second.mSocket,
                         std::stringstream(dynamic_cast<ClientSession *>(record.second.mSessionInfo.get())->
                         createLoginRequest(login,
                         password)));
        }

        return { };
    }

    bool sendMessage(std::string message)
    {
        if (mIsStarted)
        {
            auto &record = mConnectionInfo.getConnectionRecords().getLastRecord();

            return write(record.second.mSocket,
                         std::stringstream(dynamic_cast<ClientSession *>(record.second.mSessionInfo.get())->
                         createMessageRequest(message)));
        }

        return { };
    }

    bool sendSuperMessage(void)
    {
        return { };
    }

    bool sendPing(void)
    {
        if (mIsStarted)
        {
            auto &record = mConnectionInfo.getConnectionRecords().getLastRecord();

            return write(record.second.mSocket,
                         std::stringstream(dynamic_cast<ClientSession *>(record.second.mSessionInfo.get())->createPingRequest()));
        }

        return { };
    }

    bool sendLogout(void)
    {
        if (mIsStarted)
        {
            auto &record = mConnectionInfo.getConnectionRecords().getLastRecord();

            return write(record.second.mSocket,
                         std::stringstream(dynamic_cast<ClientSession *>(record.second.mSessionInfo.get())->createLogoutRequest()));
        }

        return { };
    }

private:
    SOCKET getDestination(void) override
    {
        return mConnectionInfo.getConnectionRecords().getLastRecord().second.mSocket;
    }

    int mTempNumber;

public:
    Client(decltype (mFnRead) fnRead,
           decltype (mFnConnect) fnConnect,
           decltype (mFnCheckoutSession) fnCheckoutSession,
           int tempNumber) :
        Server(fnRead,
               fnConnect,
               fnCheckoutSession),
        mTempNumber { tempNumber }
    { }

    ~Client() override
    { }

    int getTempNumber(void) const
    {
        return mTempNumber;
    }

    bool start(void) override
    {
        mConnectionInfo.prepareClient();

        if (mConnectionInfo.add<Client, std::string>("127.0.0.1", getTempNumber()))
        {
            SessionInfo session;

            if (mFnConnect(mConnectionInfo.getNextConnectionId(), session))
            {
                mConnectionThread = std::thread { receiveTask<Client>,
                    std::cref(mStop),
                    mConnectionInfo.getConnectionRecords().getLastRecord().second.mSocket,
                    std::ref(mConnectionInfo),
                    std::cref(mParicipantsDb),
                    std::ref(mParticipantsLoggedOn),
                    std::ref(mFnRead),
                    std::ref(mFnCheckoutSession) };
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
#ifndef SEPARATE_CLIENT
std::array<Client *, TH_AMOUNT> pClient;
#endif
//

bool createServerDb(std::shared_ptr<tParticipantsDb> &sessionsDb)
{
    tParticipantsDb simpleParticipantsDb;

    for (int i { }; i < TH_AMOUNT; ++i)
        simpleParticipantsDb.emplace_back(std::string(u8R"(test_login)") + std::to_string(i), u8R"(test_password)" + std::to_string(i));

    sessionsDb = std::make_shared<tParticipantsDb>(simpleParticipantsDb);

    return { true };
}

std::tuple<Server::ReplyResult, std::string, std::string> checkoutSessionServerSite(tClientInfo &clientInfo,
                                                                                    const std::shared_ptr<tParticipantsDb> &participantsDb,
                                                                                    tParticipantsDb &participantsLoggedOn)
{
    std::string answer;

    if (Protocol::RecognitionResult result;
        Protocol::RecognitionResult::Success ==
        (result = clientInfo.mProtocolState.parseVerifyAndGetAnswer(clientInfo.mData,
        std::ref(*clientInfo.mSessionInfo),
        std::cref(participantsDb),
        participantsLoggedOn,
        answer)))
    {
        if (ProtocolId::Logout == clientInfo.mSessionInfo->getProtocol())
            return { Server::ReplyResult::FinishSession, answer, { } };
        else if (ProtocolId::Message == clientInfo.mSessionInfo->getProtocol())
            return { Server::ReplyResult::ReplyAndPropagate,
            answer,
            dynamic_cast<ServerSession *>(clientInfo.mSessionInfo.get())->createSuperMessageRequest() };
        else if (ProtocolId::SuperMessage == clientInfo.mSessionInfo->getProtocol())
            return { Server::ReplyResult::None, answer, { } };
        else
            return { Server::ReplyResult::JustReply, answer, { } };
    }
    else if (Protocol::RecognitionResult::UnsupportedInfo == result ||
             Protocol::RecognitionResult::WrongState == result)
    {
        clientInfo.mData.clear();
        return { Server::ReplyResult::JustReply, answer, { } };
    }
    else if (Protocol::RecognitionResult::UnfinishedRecord == result)
        return { Server::ReplyResult::JustReply, answer, { } };

    return { };
}

std::tuple<Server::ReplyResult, std::string, std::string> checkoutSessionClientSite(tClientInfo &clientInfo,
                                                                                    const std::shared_ptr<tParticipantsDb> &participantsDb,
                                                                                    tParticipantsDb &participantsLoggedOn)
{
    Protocol::RecognitionResult recognitionResult;

    if (SessionInfo responseInfo { clientInfo.mProtocolState.lookupResponse(clientInfo.mData,
        *clientInfo.mSessionInfo, recognitionResult) };
        Protocol::RecognitionResult::Success == recognitionResult)
    {
        if (ProtocolId::Logout == responseInfo.getProtocol() &&
            responseInfo.hasResponse())
            return { Server::ReplyResult::FinishSession, { }, { } };
        else if (ProtocolId::None != responseInfo.getProtocol())
            return { Server::ReplyResult::JustReply, { }, { } };
    }
    else if (Protocol::RecognitionResult::UnfinishedRecord == recognitionResult)
        return { Server::ReplyResult::NeedMoreInfo, { }, { } };

    return { };
}

bool connectServer(uint64_t id, SessionInfo &sessionInfo)
{
    sessionInfo.provideVitalData("plain-auth");
    return { true };
}
#ifndef SEPARATE_CLIENT
bool connectClient(uint64_t id, SessionInfo &sessionInfo)
{
    return { true };
}
#endif
bool readServer(SOCKET socket, std::stringstream &&data)
{
    return pServer->write(socket, std::move(data));
}
#ifndef SEPARATE_CLIENT
struct sessInfoTemp
{
public:
    sessInfoTemp(const std::string login, const std::string password) :
        mLogin { login },
        mPassword { password },
        mIsRegistered { }
    { }

    uint64_t mId;
    std::string mLogin;
    std::string mPassword;
    std::string mSession;
    std::string mMessage;
    bool mIsRegistered;
};

static std::vector<sessInfoTemp> sessData;

bool readClient(SOCKET socket, std::stringstream &&data)
{
    const auto num = static_cast<int>(socket);
    static std::mutex sessMutex;
    Protocol response;
    SessionInfo responseInfo;
    std::string answer;

    if (response.lookupResponse(std::move(data), responseInfo, answer))
    {
        switch (responseInfo.getProtocol())
        {
        case ProtocolId::Hello:
            sessData[num].mId = responseInfo.getId();
            std::cout << std::endl <<
                "Id: " << responseInfo.getId() << std::endl <<
                "Command: " << responseInfo.getCommand() << std::endl <<
                "Auth method: " << responseInfo.getAuth_method() << std::endl;
            break;
        case ProtocolId::Login:
            sessData[num].mId = responseInfo.getId();
            sessData[num].mSession = responseInfo.getSession();

            std::cout << std::endl <<
                "Id: " << responseInfo.getId() << std::endl <<
                "Command: " << responseInfo.getCommand() << std::endl <<
                "Status: " << responseInfo.getStatus() << std::endl;

            if (responseInfo.getSession().empty())
                std::cout << "Message: " << responseInfo.getMessage() << std::endl;
            else
                std::cout << "Session: " << responseInfo.getSession() << std::endl;

            break;
        case ProtocolId::Message:
            sessData[num].mId = responseInfo.getId();
            std::cout << std::endl <<
                "Id: " << responseInfo.getId() << std::endl <<
                "Command: " << responseInfo.getCommand() << std::endl <<
                "Status: " << responseInfo.getStatus() << std::endl;

            if (!responseInfo.getMessage().empty())
                std::cout << "Message: " << responseInfo.getMessage() << std::endl;
            else
                std::cout << "Client Id: " << responseInfo.getClient_id() << std::endl;

            break;
        case ProtocolId::SuperMessage:
            if (const auto id = responseInfo.getId();
                sessData[num].mId != id)
            {
                sessData[num].mId = id;
                std::cout << std::endl <<
                    "Id: " << responseInfo.getId() << std::endl <<
                    "Command: " << responseInfo.getCommand() << std::endl <<
                    "Status: " << responseInfo.getStatus() << std::endl;

                if (!responseInfo.getMessage().empty())
                    std::cout << "Message: " << responseInfo.getMessage() << std::endl;
                else
                    std::cout << "Client Id: " << responseInfo.getClient_id() << std::endl;

                std::cout << "Text: " << responseInfo.getBody() << std::endl;
            }
            else
            {
                std::cout << responseInfo.getBody();
            }

            break;
        case ProtocolId::Ping:
            sessData[num].mId = responseInfo.getId();
            std::cout << std::endl <<
                "Id: " << responseInfo.getId() << std::endl <<
                "Command: " << responseInfo.getCommand() << std::endl <<
                "Status: " << responseInfo.getStatus() << std::endl;

            if (!responseInfo.getMessage().empty())
                std::cout << "Message: " << responseInfo.getMessage() << std::endl;

            break;
        case ProtocolId::Logout:
            sessData[num].mId = responseInfo.getId();
            std::cout << std::endl <<
                "Id: " << responseInfo.getId() << std::endl <<
                "Command: " << responseInfo.getCommand() << std::endl <<
                "Status: " << responseInfo.getStatus() << std::endl;


            setClientReady(num);
            break;
        case ProtocolId::None:
            ++gNone;
        default:
            return {};
        }
    }

    return true;
}

int gTotalClientsRemain;
#endif#pragma once
