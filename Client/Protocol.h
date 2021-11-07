#include "json.hpp"

#define RECV_BUF 512

#pragma comment(lib, "rpcrt4.lib")

enum class ProtocolId
{
    None,
    Hello,
    Login,
    Message,
    SuperMessage,
    Ping,
    Logout
};

enum class ProtocolIdMove
{
    ExpectHello,
    ExpectLogin,
    ExpectAfterAuth
};

using tParticipant =
struct Participant
{
public:
    Participant() = default;
    Participant(std::string login,
                std::string password) :
        mLogin { login },
        mPassword { password }
    { }

    std::string mLogin;
    std::string mPassword;

    bool operator ==(const Participant &other) const
    {
        return mLogin == other.mLogin &&
            mPassword == other.mPassword;
    }
};

class ISessionRequest
{
public:
    virtual ~ISessionRequest() = default;

    virtual std::string createHelloRequest(void) = 0;
    virtual std::string createLoginRequest(std::string login,
                                           std::string password) = 0;
    virtual std::string createMessageRequest(std::string message) = 0;
    virtual std::string createSuperMessageRequest(void) = 0;
    virtual std::string createPingRequest(void) = 0;
    virtual std::string createLogoutRequest(void) = 0;
};

class SessionInfo
{
public:
    SessionInfo() :
        mId {},
        mProtocolId { ProtocolId::None },
        mTransision { ProtocolIdMove::ExpectHello }
    { }

    virtual ~SessionInfo() = default;

    ProtocolId getProtocol(void) const
    {
        return mProtocolId;
    }

    ProtocolIdMove getTransision(void) const
    {
        return mTransision;
    }

    void switchStateUp(void)
    {
        if ((ProtocolId::Hello == mProtocolId ||
            ProtocolId::None == mProtocolId) &&
            ProtocolIdMove::ExpectHello == mTransision)
            mTransision = ProtocolIdMove::ExpectLogin;
        else if (ProtocolId::Login == mProtocolId &&
                 ProtocolIdMove::ExpectLogin == mTransision)
            mTransision = ProtocolIdMove::ExpectAfterAuth;
    }

    void resetState(void)
    {
        mProtocolId = ProtocolId::None;
        mTransision = ProtocolIdMove::ExpectHello;
    }

    void setProtocol(const ProtocolId &protocol)
    {
        mProtocolId = protocol;
    }

    virtual std::string createResponse(bool isGood = true)
    {
        return { };
    }

    void provideVitalData(const std::string &authMethod)
    {
        mAuth_method = authMethod;
    }

    void assignId(uint64_t id)
    {
        mId = id;
    }

    SessionInfo &operator =(const SessionInfo &rhs)
    {
        mProtocolId = rhs.mProtocolId;
        mTransision = rhs.mTransision;

        //if (mId != rhs.mId)
        //mId++;// = rhs.mId;

        if (mCommand != rhs.mCommand && !rhs.mCommand.empty())
            mCommand = rhs.mCommand;

        if (mAuth_method != rhs.mAuth_method && !rhs.mAuth_method.empty())
            mAuth_method = rhs.mAuth_method;

        if (mParticipant.mLogin != rhs.mParticipant.mLogin && !rhs.mParticipant.mLogin.empty())
            mParticipant.mLogin = rhs.mParticipant.mLogin;

        if (mParticipant.mPassword != rhs.mParticipant.mPassword && !rhs.mParticipant.mPassword.empty())
            mParticipant.mPassword = rhs.mParticipant.mPassword;

        if (mStatus != rhs.mStatus && !rhs.mStatus.empty())
            mStatus = rhs.mStatus;

        if (mSession != rhs.mSession && !rhs.mSession.empty())
            mSession = rhs.mSession;

        if (mMessage != rhs.mMessage && !rhs.mMessage.empty())
            mMessage = rhs.mMessage;

        if (mBody != rhs.mBody && !rhs.mBody.empty())
            mBody = rhs.mBody;

        if (mClient_id != rhs.mClient_id && !rhs.mClient_id.empty())
            mClient_id = rhs.mClient_id;

        if (mSender_login != rhs.mSender_login && !rhs.mSender_login.empty())
            mSender_login = rhs.mSender_login;

        return *this;
    }

    bool hasResponse(void) const
    {
        return "ok" == mStatus;
    }

    //
    auto getId(void) const
    {
        return mId;
    }

    auto getCommand(void) const
    {
        return mCommand;
    }
    auto getAuth_method(void) const
    {
        return mAuth_method;
    }

    auto getCredentials(void) const
    {
        return mParticipant;
    }

    auto getStatus(void) const
    {
        return mStatus;
    }

    auto getSession(void) const
    {
        return mSession;
    }

    auto getMessage(void) const
    {
        return mMessage;
    }

    auto getBody(void) const
    {
        return mBody;
    }

    auto getClient_id(void) const
    {
        return mClient_id;
    }

    auto getSender_login(void) const
    {
        return mSender_login;
    }

protected:
    ProtocolId mProtocolId;
    ProtocolIdMove mTransision;

    uint64_t mId;
    std::string mCommand;
    std::string mAuth_method;
    tParticipant mParticipant;
    std::string mStatus;
    std::string mSession;
    std::string mMessage;
    std::string mBody;
    std::string mClient_id;
    std::string mSender_login;
};

class ServerSession :
    public ISessionRequest,
    public SessionInfo
{
public:
    ServerSession() = default;
    ~ServerSession() = default;

    ServerSession(const ServerSession &lhs) = delete;
    ServerSession &operator =(const ServerSession &lhs) = delete;
    ServerSession(ServerSession &&rhs) = delete;
    ServerSession &operator =(ServerSession &&rhs) = delete;

    std::string createHelloRequest(void) override
    {
        return { };
    }

    std::string createLoginRequest(std::string login,
                                   std::string password) override
    {
        return { };
    }

    std::string createMessageRequest(std::string message) override
    {
        return { };
    }

    std::string createSuperMessageRequest(void) override
    {
        std::stringstream request;
        const std::string tempMessage(std::stringstream(std::string(u8R"({ "id": )" + std::to_string(mId) +
                                      u8R"(,)" + u8R"( "command": "message",)" +
                                      u8R"( "sender_login": ")" + mSender_login + u8R"(",)" +
                                      u8R"( "body": ")" + u8R"(",)" + u8R"( "session": ")" +
                                      mSession + u8R"(" })")).str());
        const auto totalEnabledLength = RECV_BUF - tempMessage.length();

        for (auto body = mBody; ;)
        {
            request << u8R"({ "id": )" << mId << u8R"(,)";
            request << u8R"( "command": "message",)";
            request << u8R"( "sender_login": ")" << mSender_login << u8R"(",)";
            request << u8R"( "session": ")" << mSession << u8R"(",)";
            request << u8R"( "body": ")";

            if (body.length() > totalEnabledLength)
            {
                auto temp = body.substr(0, totalEnabledLength);

                request << body.substr(0, totalEnabledLength) << u8R"(" })";
                auto tmp1 = request.str();
                body.erase(0, totalEnabledLength);
            }
            else
            {
                request << body << u8R"(" })";
                auto temp = request.str();
                break;
            }
        }

        //++mId;

        return request.str();
    }

    std::string createPingRequest(void) override
    {
        return { };
    }

    std::string createLogoutRequest(void) override
    {
        return { };
    }
};

class ClientSession :
    public ISessionRequest,
    public SessionInfo
{
public:
    ClientSession() = default;
    ~ClientSession() = default;

    ClientSession(const ClientSession &lhs) = delete;
    ClientSession &operator =(const ClientSession &lhs) = delete;
    ClientSession(ClientSession &&rhs) = delete;
    ClientSession &operator =(ClientSession &&rhs) = delete;

    std::string createHelloRequest(void) override
    {
        std::stringstream request;

        request << u8R"({ "id": )" << mId++ << u8R"(,)";
        request << u8R"( "command": "HELLO" })";
        return request.str();
    }

    std::string createLoginRequest(std::string login,
                                   std::string password) override
    {
        std::stringstream request;

        request << u8R"({ "id": )" << mId++ << u8R"(,)";
        request << u8R"( "command": "login",)";
        request << u8R"( "login": ")" << login << u8R"(",)";
        request << u8R"( "password": ")" << password << u8R"(" })";
        return request.str();
    }

    std::string createMessageRequest(std::string message) override
    {
        std::stringstream request;
        const std::string tempMessage(std::stringstream(std::string(u8R"({ "id": )" + std::to_string(mId) +
                                      u8R"(,)" + u8R"( "command": "message",)" +
                                      u8R"( "body": ")" + u8R"(",)" + u8R"( "session": ")" +
                                      mSession + u8R"(" })")).str());
        const auto totalEnabledLength = RECV_BUF - tempMessage.length();

        for (; ;)
        {
            request << u8R"({ "id": )" << mId << u8R"(,)";
            request << u8R"( "command": "message",)";
            request << u8R"( "session": ")" << mSession << u8R"(",)";
            request << u8R"( "body": ")";

            if (message.length() > totalEnabledLength)
            {
                request << message.substr(0, totalEnabledLength) << u8R"(" })";
                message.erase(0, totalEnabledLength);
            }
            else
            {
                request << message << u8R"(" })";
                break;
            }
        }

        mId++;

        return request.str();
    }

    std::string createSuperMessageRequest(void) override
    {
        return { };
    }

    std::string createPingRequest(void) override
    {
        std::stringstream request;

        request << u8R"({ "id": )" << mId++ << u8R"(,)";
        request << u8R"( "command": "ping",)";
        request << u8R"( "session": ")" << mSession << u8R"(" })";
        return request.str();
    }

    std::string createLogoutRequest(void) override
    {
        std::stringstream request;

        request << u8R"({ "id": )" << mId++ << u8R"(,)";
        request << u8R"( "command": "logout",)";
        request << u8R"( "session": ")" << mSession << u8R"(" })";
        return request.str();
    }
};

class HelloIn :
    public SessionInfo
{
public:
    HelloIn(std::string &&data)
    {
        nlohmann::json json = nlohmann::json::parse(data);

        mCommand = json.at("command").get<std::string>();

        if (mCommand != "HELLO" &&
            ProtocolIdMove::ExpectHello != mTransision)
            throw std::runtime_error("inaccessable state");

        mId = json.at("id").get<int>();
        mProtocolId = ProtocolId::Hello;
    }

    ~HelloIn() override = default;

    std::string createResponse(bool isGood = true) override
    {
        nlohmann::json json;
        std::stringstream temp;

        mAuth_method = u8R"(plain-text)";

        temp << u8R"({"id":)" << mId <<
            u8R"(,"command":"HELLO","auth_method":")" << mAuth_method <<
            u8R"("})";

        return json.parse(temp.str()).dump();
    }
};

class HelloOut :
    public SessionInfo
{
public:
    HelloOut(std::string &&data)
    {
        nlohmann::json json = nlohmann::json::parse(data);

        if (!json["command"].is_null())
            mCommand = json.at("command").get<std::string>();

        if (!json["id"].is_null())
            mId = json.at("id").get<int>();

        if (!json["auth_method"].is_null())
            mAuth_method = json.at("auth_method").get<std::string>();

        mProtocolId = ProtocolId::Hello;
    }

    ~HelloOut() override = default;
};

class LoginIn :
    public SessionInfo
{
public:
    LoginIn(std::string &&data)
    {
        nlohmann::json json = nlohmann::json::parse(data);

        mCommand = json.at("command").get<std::string>();

        if (mCommand != "login")
            throw std::runtime_error("inaccessable state");

        mId = json.at("id").get<int>();
        mParticipant.mLogin = json.at("login").get<std::string>();
        mParticipant.mPassword = json.at("password").get<std::string>();
        mProtocolId = ProtocolId::Login;
        mTransision = ProtocolIdMove::ExpectLogin;
    }

    ~LoginIn() override = default;

    std::string createResponse(bool isGood = true) override
    {
        nlohmann::json json;
        std::stringstream temp;

        if (isGood)
        {
            UUID uuid {};
            std::array<wchar_t, 39> buf {};
            RPC_CSTR refSize {};
            //specific
            UuidCreate(&uuid);
            mStatus = u8R"(ok)";
            UuidToStringA(&uuid, &refSize);
            mSession.assign(reinterpret_cast<const char *>(refSize));
            RpcStringFreeA(&refSize);
        }
        else
        {
            mStatus = u8R"(failed)";
            mMessage = u8R"(Проверьте правильность имени или пароля.)";
        }

        temp << u8R"({"id":)" << mId <<
            u8R"(,"command":"login")" <<
            u8R"(,"status":")" << mStatus;

        if (!mSession.empty())
            temp << u8R"(","session":")" << mSession;

        if (!mMessage.empty())
            temp << u8R"(","message":")" << mMessage;

        temp << u8R"("})";

        return json.parse(temp.str()).dump();
    }
};

class LoginOut :
    public SessionInfo
{
public:
    LoginOut(std::string &&data)
    {
        nlohmann::json json = nlohmann::json::parse(data);

        if (!json["command"].is_null())
            mCommand = json.at("command").get<std::string>();

        if (!json["id"].is_null())
            mId = json.at("id").get<int>();

        if (!json["status"].is_null())
            mStatus = json.at("status").get<std::string>();

        if (!json["session"].is_null())
            mSession = json.at("session").get<std::string>();

        if (!json["message"].is_null())
            mMessage = json.at("message").get<std::string>();

        mProtocolId = ProtocolId::Login;
    }

    ~LoginOut() override = default;
};

class MessageIn :
    public SessionInfo
{
public:
    MessageIn(std::string &&data)
    {
        nlohmann::json json = nlohmann::json::parse(data);

        mCommand = json.at("command").get<std::string>();

        if (mCommand != "message")
            throw std::runtime_error("inaccessable state");

        mId = json.at("id").get<int>();
        mBody = json.at("body").get<std::string>();
        mSession = json.at("session").get<std::string>();
        mProtocolId = ProtocolId::Message;
        mTransision = ProtocolIdMove::ExpectAfterAuth;
    }

    ~MessageIn() override = default;

    std::string createResponse(bool isGood = true) override
    {
        nlohmann::json json;
        std::stringstream temp;

        mCommand = u8R"(message_reply)";

        if (isGood)
        {
            mStatus = u8R"(ok)";
            mClient_id = std::to_string(mId);
        }
        else
        {
            mStatus = u8R"(failed)";
            mMessage = u8R"(Ошибка при отправке сообщения.)";
        }

        temp << u8R"({"id":)" << mId <<
            u8R"(,"command":")" << mCommand <<
            u8R"(","status":")" << mStatus;

        if (!mClient_id.empty())
            temp << u8R"(","client_id":")" << mClient_id;

        if (!mMessage.empty())
            temp << u8R"(","message":")" << mMessage;

        temp << u8R"("})";

        return json.parse(temp.str()).dump();
    }
};

class MessageOut :
    public SessionInfo
{
public:
    MessageOut(std::string &&data)
    {
        nlohmann::json json = nlohmann::json::parse(data);

        if (!json["command"].is_null())
            mCommand = json.at("command").get<std::string>();

        if (!json["id"].is_null())
            mId = json.at("id").get<int>();

        if (!json["status"].is_null())
            mStatus = json.at("status").get<std::string>();

        if (!json["message"].is_null())
            mMessage = json.at("message").get<std::string>();

        if (!json["client_id"].is_null())
            mClient_id = json.at("client_id").get<std::string>();

        mProtocolId = ProtocolId::Message;
    }

    ~MessageOut() override = default;
};

class SuperMessageIn :
    public SessionInfo
{
public:
    SuperMessageIn(std::string &&data)
    {
        nlohmann::json json = nlohmann::json::parse(data);

        mCommand = json.at("command").get<std::string>();

        if (mCommand != "message")
            throw std::runtime_error("inaccessable state");

        mId = json.at("id").get<int>();
        mBody = json.at("body").get<std::string>();
        mSender_login = json.at("sender_login");
        mSession = json.at("session").get<std::string>();
        mProtocolId = ProtocolId::SuperMessage;
        mTransision = ProtocolIdMove::ExpectAfterAuth;
    }

    ~SuperMessageIn() override = default;

    std::string createResponse(bool isGood = true) override
    {
        nlohmann::json json;
        std::stringstream temp;

        mCommand = u8R"(message_reply)";

        if (isGood)
        {
            mStatus = u8R"(ok)";
            mClient_id = std::to_string(mId);
        }
        else
        {
            mStatus = u8R"(failed)";
            mMessage = u8R"(Ошибка при отправке сообщения.)";
        }

        temp << u8R"({"id":)" << mId <<
            u8R"(,"command":")" << mCommand <<
            u8R"(","status":")" << mStatus;

        if (!mClient_id.empty())
            temp << u8R"(","client_id":")" << mClient_id;

        if (!mMessage.empty())
            temp << u8R"(","message":")" << mMessage;

        temp << u8R"("})";

        return json.parse(temp.str()).dump();
    }
};

class SuperMessageOut :
    public SessionInfo
{
public:
    SuperMessageOut(std::string &&data)
    {
        nlohmann::json json = nlohmann::json::parse(data);

        if (!json["command"].is_null())
            mCommand = json.at("command").get<std::string>();

        if (!json["id"].is_null())
            mId = json.at("id").get<int>();

        if (!json["body"].is_null())
            mBody = json.at("body").get<std::string>();

        if (!json["sender_login"].is_null())
            mSender_login = json.at("sender_login").get<std::string>();

        mProtocolId = ProtocolId::SuperMessage;
    }

    ~SuperMessageOut() override = default;
};

class SuperMessageReply :
    public SessionInfo
{
public:
    SuperMessageReply(std::string &&data)
    {
        nlohmann::json json = nlohmann::json::parse(data);

        mCommand = json.at("command").get<std::string>();

        if (mCommand != "message_reply")
            throw std::runtime_error("inaccessable state");

        mId = json.at("id").get<int>();
        mStatus = json.at("status").get<std::string>();

        if (!json["client_id"].is_null())
            mClient_id = json.at("client_id").get<std::string>();

        if (!json["message"].is_null())
            mMessage = json.at("message").get<std::string>();

        mProtocolId = ProtocolId::SuperMessage;
    }

    ~SuperMessageReply() override = default;
};

class PingIn :
    public SessionInfo
{
public:
    PingIn(std::string &&data)
    {
        nlohmann::json json = nlohmann::json::parse(data);

        mCommand = json.at("command").get<std::string>();

        if (mCommand != "ping")
            throw std::runtime_error("inaccessable state");

        mId = json.at("id").get<int>();
        mSession = json.at("session").get<std::string>();
        mProtocolId = ProtocolId::Ping;
        mTransision = ProtocolIdMove::ExpectAfterAuth;
    }

    ~PingIn() override = default;

    std::string createResponse(bool isGood = true) override
    {
        nlohmann::json json;
        std::stringstream temp;

        mCommand = u8R"(ping_reply)";

        if (isGood)
            mStatus = u8R"(ok)";
        else
        {
            mStatus = u8R"(failed)";
            mMessage = u8R"(Связь недоступна.)";
        }

        temp << u8R"({"id":)" << mId <<
            u8R"(,"command":")" << mCommand <<
            u8R"(","status":")" << mStatus;

        if (!mMessage.empty())
            temp << u8R"(","message":")" << mMessage;

        temp << u8R"("})";

        return json.parse(temp.str()).dump();
    }
};

class PingOut :
    public SessionInfo
{
public:
    PingOut(std::string &&data)
    {
        nlohmann::json json = nlohmann::json::parse(data);

        if (!json["command"].is_null())
            mCommand = json.at("command").get<std::string>();

        if (!json["id"].is_null())
            mId = json.at("id").get<int>();

        if (!json["status"].is_null())
            mStatus = json.at("status").get<std::string>();

        if (!json["message"].is_null())
            mMessage = json.at("message").get<std::string>();

        mProtocolId = ProtocolId::Ping;
    }

    ~PingOut() override = default;
};

class LogoutIn :
    public SessionInfo
{
public:
    LogoutIn(std::string &&data)
    {
        nlohmann::json json = nlohmann::json::parse(data);

        mCommand = json.at("command").get<std::string>();

        if (mCommand != "logout")
            throw std::runtime_error("inaccessable state");

        mId = json.at("id").get<int>();
        mSession = json.at("session").get<std::string>();
        mProtocolId = ProtocolId::Logout;
        mTransision = ProtocolIdMove::ExpectAfterAuth;
    }

    ~LogoutIn() override = default;

    std::string createResponse(bool isGood = true) override
    {
        nlohmann::json json;
        std::stringstream temp;

        mCommand = u8R"(logout_reply)";

        if (isGood)
            mStatus = u8R"(ok)";
        else
        {
            mStatus = u8R"(failed)";
            mMessage = u8R"(Неправильный идентификатор сессии.)";
        }

        temp << u8R"({"id":)" << mId <<
            u8R"(,"command":")" << mCommand <<
            u8R"(","status":")" << mStatus;

        if (!mMessage.empty())
            temp << u8R"(","message":")" << mMessage;

        temp << u8R"("})";

        return json.parse(temp.str()).dump();
    }
};

class LogoutOut :
    public SessionInfo
{
public:
    LogoutOut(std::string &&data)
    {
        nlohmann::json json = nlohmann::json::parse(data);

        if (!json["command"].is_null())
            mCommand = json.at("command").get<std::string>();

        if (!json["id"].is_null())
            mId = json.at("id").get<int>();

        if (!json["status"].is_null())
            mStatus = json.at("status").get<std::string>();

        if (!json["message"].is_null())
            mMessage = json.at("message").get<std::string>();

        mProtocolId = ProtocolId::Logout;
    }

    ~LogoutOut() override = default;
};