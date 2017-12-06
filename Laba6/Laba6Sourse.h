#ifndef LABA6SOURSE_H
#define LABA6SOURSE_H

#include <string>
#include <map>

#include "sha256.h"

class Client;
class Server;

unsigned long long Powm(unsigned long long a, unsigned long long b, unsigned long long n);
unsigned long long Hash(const std::string& message);

struct UserFields
{
	std::string salt;
	unsigned long long passVer;
};

struct SafetyField
{
	unsigned long long n;
	unsigned long long g;
	unsigned long long k;
};

struct UserInfo
{
	std::string login;
	UserFields fields;
	SafetyField safety;
};

struct InfoFromServer
{
	std::string salt;
	unsigned long long B;
};

struct InfoFromClient
{
	std::string login;
	unsigned long long A;
};

class Client
{
private:
	UserInfo _info;
	std::string _password;
	unsigned long long _a;
	unsigned long long _s;
	unsigned long long _key;
private:
	std::string _genSalt();
	unsigned long long _genNum();
	unsigned long long _genSimpleNum(int gen);
	bool _simpleNum(unsigned long long num);
	SafetyField _genNGK();
	unsigned long long _genVerificator();
public:
	unsigned long long A;
	InfoFromServer fromServ;
	unsigned long long U;
	unsigned long long M;
	unsigned long long R;
public:
	Client(const std::string& login, const std::string& password);
	~Client();

	void Registration();
	InfoFromClient Authentication(const Server& server);
	void FromServer(const InfoFromServer& fromServ);
	void Scrambler();
	void CheckScrambler();
	void GenSessionKey();
	void GenM();
	void CheckR(const Server& server);

	UserInfo GetInfoForServer() const;
};

class Server
{
private:
	std::string _filePath;
	std::map<std::string, UserInfo> _dataBase;
	unsigned long long _b;
	unsigned long long _s;
	unsigned long long _key;
private:
	void _loadDB();
	unsigned long long _genNum();
public:
	InfoFromClient fromClient;
	unsigned long long B;
	unsigned long long U;
	unsigned long long M;
	unsigned long long R;
public:
	Server(const std::string& dataBaseFile);

	void AddClient(const Client& cilent);
	InfoFromServer Authentication(const InfoFromClient& clientAuth);
	void Scrambler();
	void CheckScrambler();
	void GenSessionKey();
	void CheckM(const Client& client);
	void GenR();

	SafetyField GetSafetyField(const std::string& userLogin) const;
};

#endif // LABA6SOURSE_H