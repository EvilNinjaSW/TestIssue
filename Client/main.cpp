#include <csignal>
#include "ClientServer.h"

void subMenu(int select)
{
    system("cls");

    switch (select)
    {
    case 1:
    {
        if (!sessData[0].mIsRegistered)
        {
            std::cout << "����������� ... " << std::endl;
            pClient[0]->sendHello();
        }
        else
            std::cout << "����������� ��� ������������." << std::endl;

        system("pause");
    }
        break;
    case 2:
    {
        std::string login, password;

        std::cout << "�����������" << std::endl <<
            "������� login: ";
        std::cin >> login;
        std::cout << "������� ������: ";
        std::cin >> password;
        sessData[0].mLogin = login;
        sessData[0].mPassword = password;
        pClient[0]->sendLogin(sessData[0].mLogin, sessData[0].mPassword);
        system("pause");
    }
        break;
    case 3:
    {
        std::string message(sizeof (tReceiveBlock), ' ');

        std::cout << "�������� ��������� �������" << std::endl <<
            "������� ���������: ";
        std::cin.ignore();
        std::cin.getline(message.data(), message.length(), '\n');
        message.resize(static_cast<const size_t>(std::cin.gcount()) - 1);
        sessData[0].mMessage = message;
        pClient[0]->sendMessage(sessData[0].mMessage);
        system("pause");
    }
        break;
    case 4:
    {
        std::cout << "������� ping ... " << std::endl;
        pClient[0]->sendPing();
        system("pause");
    }
        break;
    case 5:
    {
        std::cout << "���������� �� ������� " << std::endl;
        pClient[0]->sendLogout();
        system("pause");
    }
        break;
    case 6:
    {
        std::string message("Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.Simple text test.");
        sessData[0].mMessage = message;
        pClient[0]->sendMessage(sessData[0].mMessage);
    }
        break;
    }

    std::cin.clear();
}

void menu(void)
{
    std::string select;

    do
    {
        system("cls");
        std::cout << "������ �������." <<
            std::endl << "�������� �����: " << std::endl <<
            "1 - �����������" << std::endl <<
            "2 - ����������� (�������� ������� ����)" << std::endl <<
            "3 - �������� ���������" << std::endl <<
            "4 - ������� ping" << std::endl <<
            "5 - ���������� �� �������" << std::endl << std::endl <<
            "6 - ���� �������� ���������" << std::endl << std::endl <<
            "0 - �����" << std::endl;

        std::cin >> select;

        if (select == "0")
            break;

        if (select == "1")
            subMenu(1);
        else if (select == "2")
            subMenu(2);
        else if (select == "3")
            subMenu(3);
        else if (select == "4")
            subMenu(4);
        else if (select == "5")
        {
            subMenu(5);
            break;
        }
        else if (select == "6")
            subMenu(6);
        else
        {
            std::cout << "�������� �����. ��������� ����" << std::endl;
            system("pause");
        }
    } while (true);
}

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

    std::function<bool(uint64_t, SessionInfo &)> fnClientConnect { connectClient };
    std::function<bool(SOCKET, std::stringstream &&)> fnRead { readClient };
    std::function<std::tuple<Server::ReplyResult, std::string, std::string>
        (tClientInfo &,
         const std::shared_ptr<tParticipantsDb> &,
         tParticipantsDb &)> fnCheckoutSession { checkoutSessionClientSite };

    Client *client = new Client(fnRead,
                                fnClientConnect,
                                fnCheckoutSession, 0);
    pClient[0] = client;



    for (int i { }; i < TH_AMOUNT; ++i)
        sessData.emplace_back(std::string(u8R"(test_login!)") + std::to_string(i), u8R"(test_password!)" + std::to_string(i));

    if (client->start())
    {
        setClientReady(0);
        menu();
        //waitForClientReady(0);
        client->stop();
    }
    else
    {
        std::cout << "������ �� ������� ���������." <<
            std::endl << "��������� ������ �������." << std::endl;
    }

    delete client;
    pClient[0] = nullptr;

    for (int i { }; i < TH_AMOUNT; ++i)
        if (nullptr != pClient[i])
            break;
        else
        {
            if (TH_AMOUNT == i + 1)
                break;
        }

    ++gTotalClientsRemain;
    return EXIT_SUCCESS;
}