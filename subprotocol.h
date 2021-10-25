#include "json.hpp"

#pragma comment(lib, "rpcrt4.lib")

enum class ProtocolId
{
	None,
	Hello,
	Login,
	Message,
	Ping,
	Logout
};

enum class ProtocolIdMove
{
	ExpectHello,
	ExpectLogin,
	ExpectAfterAuth
	//FromLogout
};

class SessionInfo
{
public:
	SessionInfo() :
		mId { },
		mProtocolId { ProtocolId::None },
		mTransision { ProtocolIdMove::ExpectHello }
	{ }

	virtual ~SessionInfo() { }

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
		{
			mProtocolId = ProtocolId::Login;
			mTransision = ProtocolIdMove::ExpectLogin;
		}
		else if (ProtocolId::Login == mProtocolId &&
			ProtocolIdMove::ExpectLogin == mTransision)
		{
			//mProtocolId = ProtocolId::None; //??
			mTransision = ProtocolIdMove::ExpectAfterAuth;
		}
	}

	void resetState(void)
	{
		mProtocolId = ProtocolId::None; //??
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

	//Server
	void initServerSession(uint64_t id)
	{}

	void provideVitalData(const std::string &authMethod)
	{
		mAuth_method = authMethod;
	}

	void saveData(const SessionInfo &other)
	{
		if (mId != other.mId)
			mId = other.mId;

		if (mCommand != other.mCommand && !other.mCommand.empty())
			mCommand = other.mCommand;

		if (mAuth_method != other.mAuth_method && !other.mAuth_method.empty())
			mAuth_method = other.mAuth_method;

		if (mLogin != other.mLogin && !other.mLogin.empty())
			mLogin = other.mLogin;

		if (mPassword != other.mPassword && !other.mPassword.empty())
			mPassword = other.mPassword;

		if (mStatus != other.mStatus && !other.mStatus.empty())
			mStatus = other.mStatus;

		if (mSession != other.mSession && !other.mSession.empty())
			mSession = other.mSession;

		if (mMessage != other.mMessage && !other.mMessage.empty())
			mMessage = other.mMessage;

		if (mBody != other.mBody && !other.mBody.empty())
			mBody = other.mBody;

		if (mClient_id != other.mClient_id && !other.mClient_id.empty())
			mClient_id = other.mClient_id;

		if (mSender_login != other.mSender_login && !other.mSender_login.empty())
			mSender_login = other.mSender_login;
	}

	uint64_t getId(void) const { return mId; }
	std::string getCommand(void) const{ return mCommand; };
	std::string getAuth_method(void) const{ return mAuth_method; };
	std::string getLogin(void) const{ return mLogin; };
	std::string getPassword(void) const{ return mPassword; };
	std::string getStatus(void) const{ return mStatus; };
	std::string getSession(void) const{ return mSession; };
	std::string getMessage(void) const{ return mMessage; };
	std::string getBody(void) const{ return mBody; };
	std::string getClient_id(void) const{ return mClient_id; };
	std::string getSender_login(void) const{ return mSender_login; };

	void clientAuth(const uint64_t id,
		const std::string &login,
		const std::string &password)
	{
		setId(id);
		setCommand("login");
		setLogin(login);
		setPassword(password);
	}

protected:
	void setId(const uint64_t &id) { mId = id; }
	void setCommand(const std::string &command) { mCommand = command; };
	void setAuth_method(const std::string &authMethod) { mAuth_method = authMethod; };
	void setLogin(const std::string &login) { mLogin = login; };
	void setPassword(const std::string &password) { mPassword = password; };
	void setStatus(const std::string &status) { mStatus = status; };
	void setSession(const std::string &session) { mSession = session; };
	void setMessage(const std::string &message) { mMessage = message; };
	void setBody(const std::string &body) { mBody = body; };
	void setClient_id(const std::string &clientId) { mClient_id = clientId; };
	void setSender_login(const std::string &senderLogin) { mSender_login = senderLogin; };

protected:
	ProtocolId mProtocolId;
	ProtocolIdMove mTransision;

	uint64_t mId;
	std::string mCommand;
	std::string mAuth_method;
	std::string mLogin;
	std::string mPassword;
	std::string mStatus;
	std::string mSession;
	std::string mMessage;
	std::string mBody;
	std::string mClient_id;
	std::string mSender_login;
};

class Hello :
	public SessionInfo
{
public:
	Hello(std::string &&data)
	{
		nlohmann::json json = nlohmann::json::parse(data);

		mCommand = json.at("command").get<std::string>();

		if (mCommand != "HELLO" &&
			ProtocolIdMove::ExpectHello != mTransision)
			throw std::runtime_error("inaccessable state");

		mId = json.at("id").get<int>();
		mProtocolId = ProtocolId::Hello;
	}

	~Hello() override { }

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

	~HelloOut() override { }
};

class LoginIn :
	public SessionInfo
{
public:
	LoginIn(std::string &&data)
	{
		nlohmann::json json = nlohmann::json::parse(data);

		mCommand = json.at("command").get<std::string>();

		if (mCommand != "login"/* &&
			ProtocolIdMove::ExpectHello != mTransision*/)
			throw std::runtime_error("inaccessable state");

		mId = json.at("id").get<int>();
		mLogin = json.at("login").get<std::string>();
		mPassword = json.at("password").get<std::string>();
		mProtocolId = ProtocolId::Login;
		mTransision = ProtocolIdMove::ExpectLogin;
	}

	~LoginIn() override { }

	std::string createResponse(bool isGood = true) override
	{
		nlohmann::json json;
		std::stringstream temp;

		if (isGood)
		{
			UUID uuid { };
			std::array<wchar_t, 39> buf { };
			RPC_CSTR refSize { };
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

	~LoginOut() override { }
};

class MessageIn :
	public SessionInfo
{
public:
	MessageIn(std::string &&data)
	{
		nlohmann::json json = nlohmann::json::parse(data);

		mCommand = json.at("command").get<std::string>();

		if (mCommand != "message"/* &&
			ProtocolIdMove::ExpectHello != mTransision*/)
			throw std::runtime_error("inaccessable state");

		mId = json.at("id").get<int>();
		mBody = json.at("body").get<std::string>();
		mSession = json.at("session").get<std::string>();
		mProtocolId = ProtocolId::Message;
	}

	~MessageIn() override { }
};

class MessageOut :
	public SessionInfo
{
public:
	MessageOut(std::string &&data)
	{
		throw "todo";
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

	~MessageOut() override { }
};

class PingIn :
	public SessionInfo
{
public:
	PingIn(std::string &&data)
	{
		nlohmann::json json = nlohmann::json::parse(data);

		mCommand = json.at("command").get<std::string>();

		if (mCommand != "ping"/* &&
			ProtocolIdMove::ExpectHello != mTransision*/)
			throw std::runtime_error("inaccessable state");

		mId = json.at("id").get<int>();
		mSession = json.at("session").get<std::string>();
		mProtocolId = ProtocolId::Ping;
		mTransision = ProtocolIdMove::ExpectAfterAuth;
	}

	~PingIn() override { }

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

	~PingOut() override { }
};

class LogoutIn :
	public SessionInfo
{
public:
	LogoutIn(std::string &&data)
	{
		nlohmann::json json = nlohmann::json::parse(data);

		mCommand = json.at("command").get<std::string>();

		if (mCommand != "logout"/* &&
			ProtocolIdMove::ExpectHello != mTransision*/)
			throw std::runtime_error("inaccessable state");

		mId = json.at("id").get<int>();
		mSession = json.at("session").get<std::string>();
		mProtocolId = ProtocolId::Logout;
		mTransision = ProtocolIdMove::ExpectAfterAuth;
	}

	~LogoutIn() override { }

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

	~LogoutOut() override { }
};