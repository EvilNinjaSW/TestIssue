#include <csignal>
#include "ClientServer.h"

#ifndef SEPARATE_CLIENT
void clientTestThread(int relation)
{
    std::function<bool(uint64_t, SessionInfo &)> fnClientConnect { connectClient };
    std::function<bool(SOCKET, std::stringstream &&)> fnRead { readClient };
    std::function<std::tuple<Server::ReplyResult, std::string, std::string>
        (tClientInfo &,
         const std::shared_ptr<tParticipantsDb> &,
         tParticipantsDb &)> fnCheckoutSession { checkoutSessionClientSite };

    Client *client = new Client(fnRead,
                                fnClientConnect,
                                fnCheckoutSession, relation);
    pClient[relation] = client;
    client->start();
    setClientReady(relation);
    client->sendHello();
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

    signal(SIGINT, signal_handle);
    std::function<bool(uint64_t, SessionInfo &)> fnClientConnect { connectServer };
    std::function<bool(SOCKET, std::stringstream &&)> fnClientRead { readServer };
    std::function<bool(std::shared_ptr<tParticipantsDb> &)> fnCreateServerDb { createServerDb };
    std::function<std::tuple<Server::ReplyResult, std::string, std::string>
        (tClientInfo &,
         const std::shared_ptr<tParticipantsDb> &,
         tParticipantsDb &)> fnCheckoutSession { checkoutSessionServerSite };
    Server server(fnClientRead, fnClientConnect, fnCheckoutSession, fnCreateServerDb);

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