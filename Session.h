#include "Protocol.h"

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
                                              tParticipantsDb &participantsLoggedOn,
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
                    const auto id = mGenericProtocol.getId();
                    //ALLOW AND DENY logic here
                    if (ProtocolIdMove::ExpectHello == sessionInfo.getTransision() &&
                        ProtocolIdMove::ExpectHello == mGenericProtocol.getTransision() &&
                        ProtocolId::Hello == mGenericProtocol.getProtocol())
                    {
                        auto hello = HelloIn(std::move(actual));

                        answer = hello.createResponse();
                        mGenericProtocol = hello;
                        //
                        mGenericProtocol.assignId(id);
                        //
                        mGenericProtocol.switchStateUp();

                        sessionInfo = mGenericProtocol;
                        return RecognitionResult::Success;
                    }
                    else if (ProtocolIdMove::ExpectLogin == sessionInfo.getTransision() &&
                             ProtocolIdMove::ExpectLogin == mGenericProtocol.getTransision() &&
                             ProtocolId::Login == mGenericProtocol.getProtocol())
                    {
                        auto login = LoginIn(std::move(actual));

                        for (const auto &element : *participantsDb.get())
                        {
                            if (const auto credentials = mGenericProtocol.getCredentials();
                                element.mLogin == credentials.mLogin &&
                                element.mPassword == credentials.mPassword)
                            {
                                const auto &found = std::find_if_not(std::cbegin(participantsLoggedOn), std::cend(participantsLoggedOn),
                                                                     [&](std::decay<decltype (participantsLoggedOn)>::type::const_reference participant)
                                {
                                    return participant.mLogin != element.mLogin &&
                                        participant.mPassword != element.mPassword;
                                });

                                if (std::cend(participantsLoggedOn) == found)
                                {
                                    participantsLoggedOn.emplace_back(element);
                                    answer = login.createResponse();
                                    mGenericProtocol = login;
                                    //
                                    mGenericProtocol.assignId(id);
                                    //
                                    mGenericProtocol.switchStateUp();
                                    sessionInfo = mGenericProtocol;
                                }
                                else
                                    answer = login.createResponse(false);

                                return RecognitionResult::Success;
                            }
                        }

                        answer = login.createResponse(false);
                        mGenericProtocol = login;
                        //
                        mGenericProtocol.assignId(id);
                        //
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
                                //
                                mGenericProtocol.assignId(id);
                                //
                            }
                        }
                        else if (ProtocolId::SuperMessage == mGenericProtocol.getProtocol())
                        {
                            if (mGenericProtocol.getSession() != sessionInfo.getSession())
                            {
                                return RecognitionResult::Success;
                            }
                            else
                            {
                                auto superMessage = SuperMessageReply(std::move(actual));

                                mGenericProtocol = superMessage;
                                //
                                mGenericProtocol.assignId(id);
                                //
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
                                //
                                mGenericProtocol.assignId(id);
                                //
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
                                //
                                mGenericProtocol.assignId(id);
                                //
                            }
                        }

                        sessionInfo = mGenericProtocol;
                        return RecognitionResult::Success;
                    }
                    else
                    {
                        if (ProtocolId::Hello == mGenericProtocol.getProtocol())
                        {
                            auto hello = HelloIn(std::move(actual));

                            answer = hello.createResponse(false);
                        }
                        else if (ProtocolId::Login == mGenericProtocol.getProtocol())
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
                        //
                        mGenericProtocol.assignId(id);
                        //
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
                               SessionInfo &sessionInfo,
                               RecognitionResult &recognitionResult)
    {
        SessionInfo reply;

        if (std::string actual;
            RecognitionResult::Success == (recognitionResult = analyse<ProtocolTypeClient>(data, actual, reply)))
        {
            switch (reply.getProtocol())
            {
            case ProtocolId::Hello:
                sessionInfo = reply;
                break;
            case ProtocolId::Login:
                if (reply.hasResponse())
                {
                    auto login = LoginOut(std::move(actual));

                    sessionInfo = reply;
                }
                break;
            case ProtocolId::Message:
                if (reply.hasResponse())
                {
                    auto message = MessageOut(std::move(actual));

                    sessionInfo = reply;
                }
                break;
            case ProtocolId::SuperMessage:
                if (!reply.hasResponse())
                {
                    auto message = SuperMessageIn(std::move(actual));

                    message.createResponse();
                    mGenericProtocol = message;
                    sessionInfo = reply;
                }
                break;
            case ProtocolId::Ping:
                if (reply.hasResponse())
                {
                    auto ping = PingOut(std::move(actual));

                    sessionInfo = reply;
                }
                break;
            case ProtocolId::Logout:
                if (reply.hasResponse())
                {
                    auto logout = LoginOut(std::move(actual));

                    sessionInfo = reply;
                }
                break;
            }
        }

        return reply;
    }

    bool lookupResponse(std::stringstream &&data, SessionInfo &responseInfo, std::string &answer)
    {
        try
        {
            nlohmann::json json = nlohmann::json::parse(data.str());
            const auto command = json.at("command").get<std::string>();

            if (command == "HELLO")
            {
                auto hello = HelloOut(std::move(data.str()));
                const auto id = hello.getId();

                responseInfo = hello;
                responseInfo.assignId(id);

                return true;
            }
            else if (command == "login")
            {
                auto login = LoginOut(std::move(data.str()));
                const auto id = login.getId();

                responseInfo = login;
                responseInfo.assignId(id);

                return true;
            }
            else if (command == "message_reply")
            {
                auto message = MessageOut(std::move(data.str()));
                const auto id = message.getId();

                responseInfo = message;
                responseInfo.assignId(id);

                return true;
            }
            else if (command == "message")
            {
                auto message = SuperMessageIn(std::move(data.str()));
                const auto id = message.getId();

                answer = message.createResponse();
                mGenericProtocol = message;
                responseInfo = mGenericProtocol;
                responseInfo.assignId(id);

                return true;
            }
            else if (command == "ping_reply")
            {
                auto ping = PingOut(std::move(data.str()));
                const auto id = ping.getId();

                responseInfo = ping;
                responseInfo.assignId(id);

                return true;
            }
            else if (command == "logout_reply")
            {
                auto logout = LogoutOut(std::move(data.str()));
                const auto id = logout.getId();

                responseInfo = logout;
                responseInfo.assignId(id);

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

                mOpened = 0;
                mClosed = 0;
                return RecognitionResult::UnsupportedInfo;
            }
        }

        mOpened = 0;
        mClosed = 0;
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
            else if (command == "message_reply")
            {
                mGenericProtocol.setProtocol(ProtocolId::SuperMessage);
                //mGenericProtocol = SuperMessageOut(std::move(data));
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
            else if (command == "message")
            {
                reply = SuperMessageOut(std::move(data));
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