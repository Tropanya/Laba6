#include "Laba6Sourse.h"

#include <stdlib.h>
#include <time.h>
#include <cmath>
#include <iostream>

unsigned long long Powm(unsigned long long a, unsigned long long b, unsigned long long n)
{
	unsigned long long c = 1;
	while (b != 0)
	{
		if (b % 2 == 0)
		{
			b /= 2;
			a = (a * a) % n;
		}
		else
		{
			b--;
			c = (c * a) % n;
		}
	}
	return c;
}

unsigned long long Hash(const std::string& message)
{
	const char* kMsgChar = message.c_str();

	char output[65];
	sha256_context ctx;
	unsigned char sha256sum[32];

	sha256_starts(&ctx);
	sha256_update(&ctx, (uint8 *)kMsgChar, strlen(kMsgChar));
	sha256_finish(&ctx, sha256sum);

	for (int i = 0; i < 32; i++)
		sprintf(output + i * 2, "%02x", sha256sum[i]);

	unsigned long long res = 0;
	memcpy(&res, output, 4);

	return res;
}

std::string Client::_genSalt()
{
	srand(time(NULL));

	std::string res;
	int length = 15 + rand() % 10;

	for (int i = 0; i < length; i++)
		res += (97 + rand() % 25);

	return res;
}

unsigned long long Client::_genNum()
{
	srand(time(NULL));
	return (rand() % 3000);
}

unsigned long long Client::_genSimpleNum(int gen)
{
	srand(time(NULL));
	unsigned long long res;

	do
	{
		res = rand() % gen;
	} while (!_simpleNum(res));

	return res;
}

bool Client::_simpleNum(unsigned long long num)
{
	for (unsigned long long i = 2; i <= sqrt(num); i++)
		if (num % i == 0)
			return false;
	return true;
}

SafetyField Client::_genNGK()
{
	srand(time(NULL));
	unsigned long long n, g, k, tmp = 0;

	do
	{
		n = _genSimpleNum(15000);

		do
		{
			L1:
			if (_simpleNum(n))
				n = 2 * n + 1;
			else
			{
				n = _genSimpleNum(15000);
				goto L1;
			}
		} while (!_simpleNum(n));
		
		do
		{
			g = 2 + rand() % 20;
		} while (!_simpleNum(g));

		tmp = Powm(g, n - 1, n);
	} while (tmp != 1);

	k = 3;

	return { n, g, k };
}

unsigned long long Client::_genVerificator()
{
	std::string tmpMsg = _info.fields.salt + _password;

	unsigned long long x = 0;
	x = Hash(tmpMsg);

	unsigned long long verif = Powm(_info.safety.g, x, _info.safety.n);

	return verif;
}

Client::Client(const std::string& login, const std::string& password)
{
	this->_info.login = login;
	this->_password = password;
	this->A = 0;
	this->fromServ.B = 0;
	this->fromServ.salt = "";
	this->U = 0;
	this->_s = 0;
	this->_key = 0;
	this->M = 0;
	this->R = 0;
}

Client::~Client()
{ }

void Client::Registration()
{
	this->_info.fields.salt = _genSalt();
	this->_info.safety = _genNGK();
	this->_info.fields.passVer = _genVerificator();
}

InfoFromClient Client::Authentication(const Server& server)
{
	this->_a = _genNum();
	_info.safety = server.GetSafetyField(this->_info.login);

	this->A = Powm(_info.safety.g, this->_a, _info.safety.n);

	return { _info.login, A };
}

void Client::FromServer(const InfoFromServer& fromServ)
{
	this->fromServ.B = fromServ.B;
	this->fromServ.salt = fromServ.salt;

	if (this->fromServ.B == 0)
	{
		std::cout << "[Client] Failed to connect (B == 0)" << std::endl;
		exit(0);
	}
}

void Client::Scrambler()
{
	std::string first = std::to_string(this->A);
	std::string second = std::to_string(this->fromServ.B);
	std::string tmpMsg = first + second;

	this->U = Hash(tmpMsg);
}

void Client::CheckScrambler()
{
	if (this->U == 0)
	{
		std::cout << "[Client] Failed to connect (U == 0)" << std::endl;
		exit(0);
	}
}

void Client::GenSessionKey()
{
	std::string tmpMsg = fromServ.salt + _password;

	unsigned long long x = 0;
	x = Hash(tmpMsg);

	unsigned long long base = this->fromServ.B - this->_info.safety.k * Powm(this->_info.safety.g, x, this->_info.safety.n);
	unsigned long long exponent = this->_a + U * x;
	this->_s = Powm(base, exponent, this->_info.safety.n);

	std::string keyMsg = std::to_string(this->_s);

	this->_key = Hash(keyMsg);
}

void Client::GenM()
{
	unsigned long long n = 0, g = 0, i = 0;

	n = Hash(std::to_string(this->_info.safety.n));
	g = Hash(std::to_string(this->_info.safety.g));
	i = Hash(this->_info.login);
	unsigned long long NxorG = 0;
	NxorG = n ^ g;

	std::string m = std::to_string(NxorG) + std::to_string(i) + std::to_string(this->_s) +
					std::to_string(this->A) + std::to_string(this->fromServ.B) + std::to_string(this->_key);

	this->M = Hash(m);
}

void Client::CheckR(const Server& server)
{
	std::string r = std::to_string(this->A) + std::to_string(this->M) + std::to_string(this->_key);
	this->R = Hash(r);

	if (this->R == server.R)
		std::cout << "Successful connection!" << std::endl;
	else
	{
		std::cout << "[Client] Failed to connect (R != R)" << std::endl;
		exit(0);
	}
}

UserInfo Client::GetInfoForServer() const
{
	return this->_info;
}

void Server::_loadDB()
{
	FILE* file;
	file = fopen(_filePath.c_str(), "r");
	char str[255];

	UserInfo info;
	char* login = new char;
	char* salt = new char;
	unsigned long long ver = 0, n = 0, g = 0, k = 0;

	while (!feof(file))
	{
		fgets(str, 255, file);
		sscanf(str, "Login: %s Salt: %s VPassword: %u NGK: %u, %u, %u",
			login, salt, &ver, &n, &g, &k);

		std::string strLogin(login);
		std::string strSalt(salt);

		info = { strLogin, { strSalt, ver }, { n, g, k } };

		_dataBase.insert(std::pair<std::string, UserInfo>(info.login, info));
	}

	fclose(file);
}

unsigned long long Server::_genNum()
{
	srand(time(NULL));
	return (rand() % 3000);
}

Server::Server(const std::string& dataBaseFile)
{
	this->_filePath = dataBaseFile;
	_loadDB();
	this->fromClient.A = 0;
	this->fromClient.login = "";
	this->B = 0;
	this->U = 0;
	this->_s = 0;
	this->_key = 0;
	this->M = 0;
	this->R = 0;
}

void Server::AddClient(const Client& cilent)
{
	int count = 0;
	UserInfo userInfo;
	userInfo = cilent.GetInfoForServer();

	for (auto i = _dataBase.begin(); i != _dataBase.end(); ++i)
		if (i->first == userInfo.login)
			count++;

	FILE* file;
	file = fopen(_filePath.c_str(), "a");

	if (!count)
	{
		fprintf(file, "Login: %-30s Salt: %-30s VPassword: %u ",
			userInfo.login.c_str(), userInfo.fields.salt.c_str(), userInfo.fields.passVer);

		fprintf(file, "NGK: %u, ", userInfo.safety.n);
		fprintf(file, "%u, ", userInfo.safety.g);
		fprintf(file, "%u\n", userInfo.safety.k);

		_dataBase.insert(std::pair<std::string, UserInfo>(userInfo.login, userInfo));
	}

	fclose(file);
}

InfoFromServer Server::Authentication(const InfoFromClient& clientAuth)
{
	this->fromClient.A = clientAuth.A;
	this->fromClient.login = clientAuth.login;

	if (this->fromClient.A == 0)
	{
		std::cout << "[Server] Failed to connect (A == 0)" << std::endl;
		exit(0);
	}

	this->_b = _genNum();
	UserInfo info = _dataBase.find(this->fromClient.login)->second;

	this->B = info.safety.k * info.fields.passVer + Powm(info.safety.g, this->_b, info.safety.n);

	return { info.fields.salt, B };
}

void Server::Scrambler()
{
	std::string first = std::to_string(this->fromClient.A);
	std::string second = std::to_string(this->B);
	std::string tmpMsg = first + second;

	this->U = Hash(tmpMsg);
}

void Server::CheckScrambler()
{
	if (this->U == 0)
	{
		std::cout << "[Server] Failed to connect (U == 0)" << std::endl;
		exit(0);
	}
}

void Server::GenSessionKey()
{
	UserInfo info = _dataBase.find(this->fromClient.login)->second;

	this->_s = Powm(this->fromClient.A * Powm(info.fields.passVer, this->U, info.safety.n), this->_b, info.safety.n);

	std::string keyMsg = std::to_string(this->_s);

	this->_key = Hash(keyMsg);
}

void Server::CheckM(const Client& client)
{
	UserInfo info = client.GetInfoForServer();

	unsigned long long n = 0, g = 0, i = 0;

	n = Hash(std::to_string(info.safety.n));
	g = Hash(std::to_string(info.safety.g));
	i = Hash(info.login);
	unsigned long long NxorG = 0;
	NxorG = n ^ g;

	std::string m = std::to_string(NxorG) + std::to_string(i) + std::to_string(this->_s) +
		std::to_string(this->fromClient.A) + std::to_string(this->B) + std::to_string(this->_key);

	this->M = Hash(m);

	if (this->M == client.M)
		GenR();
	else
	{
		std::cout << "[Server] Failed to connect (M != M)" << std::endl;
		exit(0);
	}
}

void Server::GenR()
{
	std::string r = std::to_string(this->fromClient.A) + std::to_string(this->M) + std::to_string(this->_key);
	this->R = Hash(r);
}

SafetyField Server::GetSafetyField(const std::string& userLogin) const
{
	int count = 0;

	for (auto i = _dataBase.begin(); i != _dataBase.end(); ++i)
		if (i->first == userLogin)
			count++;

	if (!count)
	{
		std::cout << "Unknown user" << std::endl;
		exit(0);
	}

	return _dataBase.find(userLogin)->second.safety;
}