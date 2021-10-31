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
#include <csignal>
#include <iostream>

#include "subprotocol.h"

#pragma comment(lib, "ws2_32.lib")

#define SEPARATE_CLIENT

#define TH_AMOUNT 1

std::thread gTestThreads[TH_AMOUNT];

std::mutex gClientReady[TH_AMOUNT];
std::mutex gServerReady;
std::condition_variable gWaitClient[TH_AMOUNT];
std::condition_variable gWaitServer;

//test purpose only
int gHello { };
int gLogin { };
int gMessage { };
int gPing { };
int gLogout { };
int gNone { };

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

#define RECV_BUF 512
using tReceiveBlock = std::array<char, RECV_BUF>;

using tParticipant =
struct Participant
{
public:
    Participant(std::string login,
                std::string password) :
        mLogin { login },
        mPassword { password }
    { }

    std::string mLogin;
    std::string mPassword;
};
using tParticipantsDb = std::vector<tParticipant>;
using tSessionsDb = std::map<SOCKET, SessionInfo>;

using ProtocolTypeServer = void;
using ProtocolTypeClient = SessionInfo;

class Protocol
{
private:
    bool mBeginExchange;
    bool mEndExchange;
    uint64_t mOpened;
    uint64_t mClosed;

public:
    Protocol() :
        mBeginExchange {},
        mEndExchange { true },
        mOpened {},
        mClosed {}
    { }

    ~Protocol() = default;

    enum class RecognitionResult
    {
        Success,
        UnsupportedInfo,
        UnfinishedRecord,
        WrongState
    };

    enum class State
    {
        Correct,
        Wrong,
        Unsupported
    };

    RecognitionResult parseVerifyAndGetAnswer(std::string &block,
                                              SessionInfo &sessionInfo,
                                              const std::shared_ptr<tParticipantsDb> &participantsDb,
                                              std::string &answer)
    {
        if (block.empty())
            return { };

        if (!mBeginExchange &&
            mEndExchange)
        {
            if (RecognitionResult result { RecognitionResult::UnsupportedInfo };
                block[0] == '{')
            {
                mBeginExchange = true;
                mEndExchange = false;

                if (std::string actual;
                    RecognitionResult::Success == (result = analyse<>(block, actual)))
                {
                    //ALLOW AND DENY logic here
                    if (ProtocolIdMove::ExpectHello == sessionInfo.getTransision() &&
                        ProtocolIdMove::ExpectHello == mGenericProtocol.getTransision() &&
                        ProtocolId::Hello == mGenericProtocol.getProtocol())
                    {
                        auto hello = HelloIn(std::move(actual));

                        answer = hello.createResponse();
                        mGenericProtocol = hello;
                        mGenericProtocol.switchStateUp();
                        sessionInfo.switchStateUp();
                        sessionInfo.saveData(mGenericProtocol);
                        return RecognitionResult::Success;
                    }
                    else if (ProtocolIdMove::ExpectLogin == sessionInfo.getTransision() &&
                             ProtocolIdMove::ExpectLogin == mGenericProtocol.getTransision() &&
                             ProtocolId::Login == mGenericProtocol.getProtocol())
                    {
                        auto login = LoginIn(std::move(actual));

                        for (const auto &element : *participantsDb.get())
                        {
                            if (element.mLogin == mGenericProtocol.getLogin())
                                if (element.mPassword == mGenericProtocol.getPassword())
                                {
                                    answer = login.createResponse();
                                    mGenericProtocol = login;
                                    mGenericProtocol.switchStateUp();
                                    sessionInfo.switchStateUp();
                                    sessionInfo.saveData(mGenericProtocol);
                                    return RecognitionResult::Success;
                                }
                        }

                        answer = login.createResponse(false);
                        mGenericProtocol = login;
                        return RecognitionResult::Success;
                    }
                    else if (ProtocolIdMove::ExpectAfterAuth == sessionInfo.getTransision() &&
                             ProtocolIdMove::ExpectAfterAuth == mGenericProtocol.getTransision())
                    {
                        if (ProtocolId::Message == mGenericProtocol.getProtocol())
                        {
                            if (mGenericProtocol.getSession() != sessionInfo.getSession())
                            {
                                auto message = MessageIn(std::move(actual));

                                answer = message.createResponse(false);
                                return RecognitionResult::Success;
                            }
                            else
                            {
                                auto message = MessageIn(std::move(actual));

                                answer = message.createResponse();
                                mGenericProtocol = message;
                            }
                        }
                        else if (ProtocolId::Ping == mGenericProtocol.getProtocol())
                        {
                            if (mGenericProtocol.getSession() != sessionInfo.getSession())
                            {
                                auto ping = PingIn(std::move(actual));

                                answer = ping.createResponse(false);
                                return RecognitionResult::Success;
                            }
                            else
                            {
                                auto ping = PingIn(std::move(actual));

                                answer = ping.createResponse();
                                mGenericProtocol = ping;
                            }
                        }
                        else if (ProtocolId::Logout == mGenericProtocol.getProtocol())
                        {
                            if (mGenericProtocol.getSession() != sessionInfo.getSession())
                            {
                                auto logout = LogoutIn(std::move(actual));

                                answer = logout.createResponse(false);
                                return RecognitionResult::Success;
                            }
                            else
                            {
                                auto logout = LogoutIn(std::move(actual));

                                answer = logout.createResponse();
                                mGenericProtocol = logout;
                            }
                        }

                        sessionInfo.setProtocol(mGenericProtocol.getProtocol());
                        sessionInfo.saveData(mGenericProtocol);
                        //answer = mGenericProtocol.createResponse();
                        return RecognitionResult::Success;
                    }
                    else
                    {
                        if (ProtocolId::Login == mGenericProtocol.getProtocol())
                        {
                            auto login = LoginIn(std::move(actual));

                            answer = login.createResponse(false);
                        }
                        else if (ProtocolId::Message == mGenericProtocol.getProtocol())
                        {
                            auto message = MessageIn(std::move(actual));

                            answer = message.createResponse(false);
                        }
                        else if (ProtocolId::Ping == mGenericProtocol.getProtocol())
                        {
                            auto ping = PingIn(std::move(actual));

                            answer = ping.createResponse(false);
                        }
                        else if (ProtocolId::Logout == mGenericProtocol.getProtocol())
                        {
                            auto logout = LogoutIn(std::move(actual));

                            answer = logout.createResponse(false);
                        }

                        mGenericProtocol = sessionInfo;
                        return RecognitionResult::Success;
                    }

                    return RecognitionResult::UnsupportedInfo;
                }
                else
                    return result;
            }
            else
                return result;
        }

        if (mBeginExchange &&
            !mEndExchange)
        {
            RecognitionResult result { RecognitionResult::UnsupportedInfo };

            if (std::string actual;
                RecognitionResult::Success == analyse<>(block, actual))
            {
                answer = mGenericProtocol.createResponse();
                return RecognitionResult::Success;
            }
        }

        return RecognitionResult::UnfinishedRecord;
    }

    SessionInfo lookupResponse(std::string &data,
                               SessionInfo &sessionInfo)
    {
        SessionInfo reply;
        std::string tempData { data };

        if (std::string actual;
            RecognitionResult::Success == analyse<ProtocolTypeClient>(tempData, actual, reply))
        {
            //sessionInfo = reply;

            switch (reply.getProtocol())
            {
            case ProtocolId::Hello:
                sessionInfo.saveData(reply);
                break;
            case ProtocolId::Login:
                if (reply.hasResponse())
                {
                    auto login = LoginOut(std::move(actual));

                    sessionInfo.saveData(reply);
                }
                break;
            case ProtocolId::Message:
                if (reply.hasResponse())
                {
                    auto message = MessageOut(std::move(actual));

                    sessionInfo.saveData(reply);
                }
                break;
            case ProtocolId::Ping:
                if (reply.hasResponse())
                {
                    auto ping = PingOut(std::move(actual));

                    sessionInfo.saveData(reply);
                }
                break;
            case ProtocolId::Logout:
                if (reply.hasResponse())
                {
                    auto logout = LoginOut(std::move(actual));

                    sessionInfo.saveData(reply);
                }
                break;
            }
        }

        return reply;
    }

    bool lookupResponse(std::stringstream &&data, SessionInfo &responseInfo)
    {
        try
        {
            nlohmann::json json = nlohmann::json::parse(data.str());
            const auto command = json.at("command").get<std::string>();

            if (command == "HELLO")
            {
                responseInfo = HelloOut(std::move(data.str()));

                return true;
            }
            else if (command == "login")
            {
                responseInfo = LoginOut(std::move(data.str()));

                return true;
            }
            else if (command == "message_reply")
            {
                responseInfo = MessageOut(std::move(data.str()));

                return true;
            }
            else if (command == "ping_reply")
            {
                responseInfo = PingOut(std::move(data.str()));

                return true;
            }
            else if (command == "logout_reply")
            {
                responseInfo = LogoutOut(std::move(data.str()));

                return true;
            }
        }
        catch (const std::exception &ex)
        {
            std::string info { ex.what() };

            info.clear();
        }

        return {};
    }

    //Protocol(const Protocol &lhs) = default;
    //Protocol &operator =(const Protocol &lhs) = default;

private:
    //Protocol(const Protocol &lhs) = delete;
    //Protocol &operator =(const Protocol &lhs) = delete;
    //Protocol(Protocol &&rhs) = delete;
    //Protocol &operator =(Protocol &&rhs) = delete;

    SessionInfo mGenericProtocol;

    template <typename... T>
    RecognitionResult analyse(std::string &restBlock, std::string &actualBlock, T &...type)
    {
        auto &data { restBlock };
        std::decay<decltype (restBlock)>::type::size_type chunkEndPosition { };

        for (std::decay<decltype (data)>::template type::template size_type i { }; i < data.size(); ++i)
        {
            if (data[i] == '{')
                ++mOpened;
            else if (data[i] == '}')
                ++mClosed;

            ++chunkEndPosition;

            if (mOpened == mClosed &&
                mOpened)
            {
                if (mOpened == mClosed)
                {
                    auto givenData = restBlock.substr(0, chunkEndPosition);

                    restBlock.erase(std::begin(restBlock), std::begin(restBlock) + chunkEndPosition);
                    mOpened = 0;
                    mClosed = 0;
                    mBeginExchange = false;
                    mEndExchange = true;

                    State state;
;
                    if constexpr (std::is_same_v<T..., ProtocolTypeServer>)
                        state = recognize(std::string(givenData));
                    else if (std::is_same_v<T..., ProtocolTypeClient>)
                        state = recognize(std::move(givenData), type...);
                    else
                        static_assert(std::is_same_v<T..., ProtocolTypeServer> ||
                                      std::is_same_v<T..., ProtocolTypeClient>);

                    switch (state)
                    {
                    case State::Correct:
                        actualBlock = std::move(givenData);
                        return RecognitionResult::Success;
                    case State::Wrong:
                        return RecognitionResult::WrongState;
                    case State::Unsupported:
                        return RecognitionResult::UnsupportedInfo;
                    }
                }

                return RecognitionResult::UnsupportedInfo;
            }
        }

        return RecognitionResult::UnfinishedRecord;
    }

    State recognize(std::string &&data)
    {
        try
        {
            nlohmann::json json = nlohmann::json::parse(data);
            const auto command = json.at("command").get<std::string>();

            if (command == "HELLO")
            {
                //if (!mGenericProtocol)
                //{
                    mGenericProtocol = HelloIn(std::move(data));
                //}
                //else
                 //   return State::Wrong;

                return State::Correct;
            }
            else if (command == "login")
            {
                //auto temporary = std::make_unique<LoginIn>(std::move(data));

                //if (mGenericProtocol)
                //{
                mGenericProtocol = LoginIn(std::move(data));//std::move(temporary);
                //}
                //else
                //    return State::Wrong;

                return State::Correct;
            }
            else if (command == "message")
            {
                //auto temporary = std::make_unique<MessageIn>(std::move(data));

                //if (mGenericProtocol)
                //{
                mGenericProtocol = MessageIn(std::move(data));// std::move(temporary);
                //}
                //else
                //    return State::Wrong;

                return State::Correct;
            }
            else if (command == "ping")
            {
                //auto temporary = std::make_unique<PingIn>(std::move(data));

                //if (mGenericProtocol)
                //{
                mGenericProtocol = PingIn(std::move(data));// std::move(temporary);
                //}
                //else
                //    return State::Wrong;

                return State::Correct;
            }
            else if (command == "logout")
            {
                //auto temporary = std::make_unique<LogoutIn>(std::move(data));

                //if (mGenericProtocol)
                //{
                mGenericProtocol = LogoutIn(std::move(data));// std::move(temporary);
                //}
                //else
                //    return State::Wrong;

                return State::Correct;
            }
        }
        catch (const std::exception &ex)
        {
            std::string info { ex.what() };

            info.clear();
        }

        return State::Unsupported;
    }

    State recognize(std::string &&data, SessionInfo &reply)
    {
        try
        {
            nlohmann::json json = nlohmann::json::parse(data);
            const auto command = json.at("command").get<std::string>();

            if (command == "HELLO")
            {
                reply = HelloOut(std::move(data));

                return State::Correct;
            }
            else if (command == "login")
            {
                reply = LoginOut(std::move(data));

                return State::Correct;
            }
            else if (command == "message_reply")
            {
                reply = MessageOut(std::move(data));

                return State::Correct;
            }
            else if (command == "ping_reply")
            {
                reply = PingOut(std::move(data));

                return State::Correct;
            }
            else if (command == "logout_reply")
            {
                reply = LogoutOut(std::move(data));

                return State::Correct;
            }
        }
        catch (const std::exception &ex)
        {
            std::string info { ex.what() };

            info.clear();
        }

        return State::Unsupported;
    }
};

/*
�����������.�
��������� �������:
{
� � "id":1,
    "command":"HELLO"
    }

    ����� �������
    {
    "id":1,
    "command":"HELLO",
    "auth_method":"plain-text"
    }

    �����������
    ��������� �������:
    {
    "id":2,
    "command":"login",
    "login":"<login>",
    "password":"<password>",
    }

    ����� �������
    {
    "id":2,
    "command":"login",
    "status":"ok",
    "session":"<UUID ������>"
    }
    ���
    {
    "id":2,
    "command":"login",
    "status":"failed",
    "message":"��������� �� ������"
    }

    ������� ���������
    ��������� �������:
    {
    � � "id":2,
        "command":"message",
        "body":"<���� ���������>",
        "session":"<UUID ������>"
        }

        ����� �������
        {
        � � "id":2,
            "command":"message_reply",
            "status":"ok",
            "client_id":"<id ��������� �������>"
            }
            ��� (� ������ ���� ������ �� �����������)
            {
            "id":2,
            "command":"message_reply",
            "status":"failed",
            "message":"��������� �� ������"
            }
            ������� ��������� � ��������
            ��������� �������:
            {
            "id":2,
            "command":"message",
            "body":"<���� ���������>",
            "sender_login":"<login>",
            "session":"<UUID ������>"
            }

            ����� �������
            {
            "id":2,
            "command":"message_reply",
            "status":"ok",
            "client_id":"<id ���������>"
            }
            ��� (� ������ ���� ������ �� �����������)
            {
            "id":2,
            "command":"message_reply",
            "status":"failed",
            "message":"��������� �� ������"
            }

            �������� ����������
            ��������� �������:
            {
            "id":2,
            "command":"ping",
            "session":"<UUID ������>"
            }

            ����� �������
            {
            "id":2,
            "command":"ping_reply",
            "status":"ok",
            }
            ��� (� ������ ���� ������ �� �����������)
            {
            "id":2,
            "command":"ping_reply",
            "status":"failed",
            "message":"��������� �� ������"
            }

            �������������
            ��������� �������:
            {
            "id":2,
            "command":"logout",
            "session":"<UUID ������>"
            }
            ����� �������
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

    bool addRecord(SOCKET socket, int temp)
    {
        tClientInfo clientInfo { socket, 4, { }, { }, { }, temp };

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
                std::lock_guard<decltype (mRecordsMutex)> lock(mRecordsMutex/*.lock()*/);

                if (mConnectionRecords.addRecord(param, temp))
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
                if (mConnectionRecords.addRecord(mMainSocket, temp))
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
    std::function<bool(SOCKET, std::stringstream &&)> mFnRead;
    std::function<bool(uint64_t, SessionInfo &)> mFnConnect;
    ConnectionInfo mConnectionInfo;
    tSessionsDb mSessionsDb;
    std::shared_ptr<tParticipantsDb> mParicipantsDb;

    virtual SOCKET getDestination()
    {
        return {};
    }

public:
    explicit Server(decltype (mFnRead) fnRead,
                    decltype (mFnConnect) fnConnect,
                    decltype (mFnCreateDb) fnCreateDb = nullptr) :
        mIsStarted {},
        mStop {},
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

                    std::thread timeoutLoginTask { timeoutLogin,
                        std::ref(connectionInfo),
                        readWriteSocket };
                    std::thread readTask { receiveTask<Server>,
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
                    tClientsId::key_type siteId {};

                    for (auto &element : connectionInfo.getConnectionRecords().getAllRecords())
                    {
                        if (element.second.mSocket == rwSocket)
                        {
                            siteId = element.first;
                            element.second.mData.append(block.data(), length);

                            for (; !element.second.mData.empty();)
                            {
                                //Protocol localProtocol;
                                std::string answer;

                                if (Protocol::RecognitionResult result;
                                    Protocol::RecognitionResult::Success ==
                                    (result = element.second.mProtocolState.parseVerifyAndGetAnswer(element.second.mData,
                                    std::ref(element.second.mSessionInfo),
                                    std::cref(participantsDb),
                                    answer)))
                                {
                                    if (read(rwSocket/*siteId*/, std::stringstream(answer)))
                                    {
                                        if (ProtocolId::Logout == element.second.mSessionInfo.getProtocol())
                                        {
                                            connectionInfo.remove<Server, SOCKET>(rwSocket);
                                            break;
                                        }
                                    }
                                }
                                else if (Protocol::RecognitionResult::UnsupportedInfo == result ||
                                         Protocol::RecognitionResult::WrongState == result)
                                {
                                    element.second.mData.clear();
                                    break;
                                }
                                else if (Protocol::RecognitionResult::UnfinishedRecord == result)
                                    break;
                            }

                            break;
                        }
                    }
                }
                else if (std::is_same_v<Client, T>)
                {
                    auto &records { connectionInfo.getConnectionRecords() };
                    tClientsId::key_type siteId {};

                    for (auto &element : records.getAllRecords())
                    {
                        if (element.second.mSocket == rwSocket)
                        {
                            //Protocol protocol;

                            siteId = element.first;
                            element.second.mData.append(block.data(), length);

                            while (true)
                            {
                                auto temp = data.str();
                                if (SessionInfo responseInfo { element.second.mProtocolState.lookupResponse(temp,
                                    std::ref(element.second.mSessionInfo)) };
                                    ProtocolId::None != responseInfo.getProtocol())
                                {
                                    if (read(element.second.temp, std::stringstream(element.second.mData)))
                                    {
                                        if (ProtocolId::Logout == responseInfo.getProtocol() &&
                                            responseInfo.hasResponse())
                                        {
                                            connectionInfo.remove<Client, SOCKET>(rwSocket);
                                            break;
                                        }
                                    }
                                }

                                element.second.mData.clear();
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
private:
    SOCKET getDestination(void) override
    {
        return mConnectionInfo.getConnectionRecords().getLastRecord().second.mSocket;
    }

    int mTempNumber;

public:
    Client(decltype (mFnRead) fnRead,
           decltype (mFnConnect) fnConnect,
           int tempNumber) :
        Server(fnRead,
               fnConnect),
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

bool connectServer(uint64_t id, SessionInfo &sessionInfo)
{
    sessionInfo.initServerSession(id);
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

    int mId;
    std::string mLogin;
    std::string mPassword;
    std::string mSession;
    bool mIsRegistered;
};

static std::vector<sessInfoTemp> sessData;

bool readClient(SOCKET socket, std::stringstream &&data)
{
    const auto num = static_cast<int>(socket);
    static std::mutex sessMutex;
    Protocol response;
    SessionInfo responseInfo;

    if (response.lookupResponse(std::move(data), responseInfo))
    {
        switch (responseInfo.getProtocol())
        {
        case ProtocolId::Hello:
        {
            decltype(sessData)::size_type ch { };

            {
                std::lock_guard<std::mutex> lock(sessMutex);

                ++gHello; 
                std::cout << "Hello " << std::to_string(gHello) << std::endl;

                for (decltype (sessData)::size_type i { }; i < sessData.size(); ++i)
                {
                    if (!sessData[i].mIsRegistered)
                    {
                        ch = i;
                        sessData[i].mIsRegistered = true;
                        break;
                    }
                }
            }

            return pClient[num]->write(0, requestLogin(2, sessData[ch].mLogin, sessData[ch].mPassword));
        }
            break;
        case ProtocolId::Login:
            ++gLogin;
            std::cout << "Login " << std::to_string(gLogin) << std::endl;

            if (responseInfo.hasResponse())
            {
                {
                    std::lock_guard<std::mutex> lock(sessMutex);

                    sessData[num].mSession = responseInfo.getSession();
                }

                return pClient[num]->write(0, std::move(requestMessage(responseInfo.getId(), u8R"(Test message.)", sessData[num].mSession)));
            }
            else
                std::cout << responseInfo.getMessage();

            break;
        case ProtocolId::Message:
            ++gMessage;
            std::cout << "Message " << std::to_string(gMessage) << std::endl;

            if (responseInfo.hasResponse())
                return pClient[num]->write(0, std::move(requestPing(responseInfo.getId(), sessData[num].mSession)));
            else
                std::cout << responseInfo.getMessage();

            break;
        case ProtocolId::Ping:
            ++gPing;
            std::cout << "Ping " << std::to_string(gPing) << std::endl;

            if (responseInfo.hasResponse())
                return pClient[num]->write(0, std::move(requestLogout(responseInfo.getId(), sessData[num].mSession)));
            else
                std::cout << responseInfo.getMessage();

            break;
        case ProtocolId::Logout:
            ++gLogout;
            std::cout << "Logout " << std::to_string(gLogout) << std::endl;
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

void clientTestThread(int relation)
{
    std::function<bool(uint64_t, SessionInfo &)> fnClientConnect { connectClient };
    std::function<bool(SOCKET, std::stringstream &&)> fnRead { readClient };

    Client *client = new Client(fnRead,
                                fnClientConnect, relation);
    pClient[relation] = client;
    client->start();
    setClientReady(relation);
    client->write(0, requestHello(relation + 1));
    waitForClientReady(relation);
    client->stop();
    delete client;
    pClient[relation] = nullptr;

    for (int i { }; i < TH_AMOUNT; ++i)
        if (nullptr != pClient[i])
            break;
        else
        {
            if (TH_AMOUNT == i + 1)
            {
                setServerReady();
                break;
            }
        }

    ++gTotalClientsRemain;
}
#endif
void __cdecl signal_handle(int sig_num)
{
    if (SIGINT == sig_num)
        exit(0);
}

int main(int argc, char **argv)
{
    std::locale appLocale("rus");
    std::locale::global(appLocale);
    std::cout.imbue(appLocale);
    std::cin.imbue(appLocale);

    std::stringstream ss;

    ss << "Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.";

    signal(SIGINT, signal_handle);
    std::function<bool(uint64_t, SessionInfo &)> fnClientConnect { connectServer };
    std::function<bool(SOCKET, std::stringstream &&)> fnClientRead { readServer };
    std::function<bool(std::shared_ptr<tParticipantsDb> &)> fnCreateServerDb { createServerDb };
    Server server(fnClientRead, fnClientConnect, fnCreateServerDb);

    //
    pServer = &server;
    //
#ifndef SEPARATE_CLIENT
    for (int i { }; i < TH_AMOUNT; ++i)
        sessData.emplace_back(std::string(u8R"(test_login)") + std::to_string(i), u8R"(test_password)" + std::to_string(i));
#endif
    server.start();
    setServerReady();
#ifndef SEPARATE_CLIENT
    std::this_thread::sleep_for(std::chrono::seconds(1));

    for (int i { }; i < TH_AMOUNT; ++i)
        gTestThreads[i] = std::move(std::thread(clientTestThread, i));
#endif
    waitForServerReady();
#ifndef SEPARATE_CLIENT
    for (int i { }; i < TH_AMOUNT; ++i)
        gTestThreads[i].join();
#endif
    server.stop();
    return EXIT_SUCCESS;
}