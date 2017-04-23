#include <iostream>
#include <sstream>
#include <algorithm>
#include <set>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>

#define MAX_EVENTS 32


int set_nonblock(int fd)
{
	int flags;
#if defined(O_NONBLOCK)
	if (-1 == (flags = fcntl(fd, F_GETFL, 0)))
		flags = 0;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#else
	flags = 1;
	return ioctl(fd, FIOBIO, &flags);
#endif
} 


int main(int argc, char const* argv[])
{
	int MasterSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	struct sockaddr_in SockAddr;
	SockAddr.sin_family = AF_INET;
	SockAddr.sin_port = htons(12345);
	SockAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	int bind_result = bind(MasterSocket, (struct sockaddr *)(&SockAddr), sizeof(SockAddr));
	if (bind_result) {
		std::cout << "Can't bind" << std::endl;
		return -1;
	}
	

	set_nonblock(MasterSocket);
	listen(MasterSocket, SOMAXCONN);
	int EPoll = epoll_create1(0);
	struct epoll_event Event;
	Event.data.fd = MasterSocket;
	Event.events = EPOLLIN;
	epoll_ctl(EPoll, EPOLL_CTL_ADD, MasterSocket, &Event);

	while (true) {
		struct epoll_event Events[MAX_EVENTS];
		int N = epoll_wait(EPoll, Events, MAX_EVENTS, -1);
		for(int i = 0; i < N; i++) {
			if (Events[i].data.fd == MasterSocket) {
				int SlaveSocket = accept(MasterSocket, 0, 0);
				set_nonblock(SlaveSocket);
				struct epoll_event Event;
				Event.data.fd = SlaveSocket;
				Event.events = EPOLLIN;
				epoll_ctl(EPoll, EPOLL_CTL_ADD, SlaveSocket, &Event);
			} else {
				static char Buffer[1024];
				int RecvResult = recv(Events[i].data.fd, Buffer, 1024, MSG_NOSIGNAL);
				if ((RecvResult == 0) && (errno != EAGAIN)) {
					shutdown(Events[i].data.fd, SHUT_RDWR);
				} else if (RecvResult > 0) {
					send(Events[i].data.fd, Buffer, RecvResult, MSG_NOSIGNAL);
					std::istringstream is(Buffer);
					std::string part;
					while(std::getline(is, part, '\n')) {
						std::cout << "part: " << part << std::endl;
						if (part.find("GET") == 0) {
							std::cout << "GET REQUEST" << std::endl;
						}
					}
				}
			}
		}
	}
	return 0;
}
