#include <iostream>

#include "Laba6Sourse.h"

int main()
{
	Server srv("DataBase.txt");
	Client cl("tropa", "12345678");
	//cl.Registration();
	//srv.AddClient(cl);

	InfoFromClient fromCln = cl.Authentication(srv);
	InfoFromServer fromSrv = srv.Authentication(fromCln);

	cl.FromServer(fromSrv);
	cl.Scrambler();
	srv.Scrambler();

	cl.CheckScrambler();
	srv.CheckScrambler();

	cl.GenSessionKey();
	srv.GenSessionKey();

	cl.GenM();
	srv.CheckM(cl);

	srv.GenR();
	cl.CheckR(srv);

	return 0;
}