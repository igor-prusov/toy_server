#include <iostream>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <set>
#include <ios>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <string.h>

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


int is_regular_file(const char *path)
{
    struct stat path_stat;
    stat(path, &path_stat);
    return S_ISREG(path_stat.st_mode);
}


int
daemonize()
{
    pid_t child;
    //fork, detach from process group leader
    if( (child=fork())<0 ) { //failed fork
        fprintf(stderr,"error: failed fork\n");
        exit(EXIT_FAILURE);
    }
    if (child>0) { //parent
        exit(EXIT_SUCCESS);
    }
    if( setsid()<0 ) { //failed to become session leader
        fprintf(stderr,"error: failed setsid\n");
        exit(EXIT_FAILURE);
    }

    //catch/ignore signals
    signal(SIGCHLD,SIG_IGN);
    signal(SIGHUP,SIG_IGN);

    //fork second time
    if ( (child=fork())<0) { //failed fork
        fprintf(stderr,"error: failed fork\n");
        exit(EXIT_FAILURE);
    }
    if( child>0 ) { //parent
        exit(EXIT_SUCCESS);
    }

    //new file permissions
    umask(0);
    //change to path directory
    //chdir("/");

    //Close all open file descriptors
    int fd;
    for( fd=sysconf(_SC_OPEN_MAX); fd>0; --fd )
    {
        close(fd);
    }

    //reopen stdin, stdout, stderr
    //stdin=fopen(infile,"r");   //fd=0
    stdout=fopen("/tmp/server_out.txt","w+");  //fd=1
    stderr=fopen("/tmp/server_err.txt","w+");  //fd=2

    return(0);
}


std::string readFile(std::string filename) {
	std::cout << "Opening file: " << filename << std::endl;
	std::ifstream t(filename);
	std::string file_str((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());	
	std::cout << "File: {" << file_str  << "}" << std::endl;
	return file_str;
}

void sendFile(int fd, std::string file) {
	std::stringstream ss;
	ss << "HTTP/1.1 200 OK\r\n";
	ss << "Content-Type: text/html\r\n";
	ss << "Content-Length: " << file.length() << "\r\n";
	ss << "\r\n";
	ss << file;
	send(fd, ss.str().c_str(), ss.str().length(), MSG_NOSIGNAL);
	//std::cout << "stream: [ " << ss.str() << "]" << std::endl;
	std::cout << "len: [ " << file.length() << "]" << std::endl;
}

void send404(int fd) {
	std::stringstream ss;
	ss << "HTTP/1.1 404 Not Found\r\n";
	ss << "\r\n";
	send(fd, ss.str().c_str(), ss.str().length(), MSG_NOSIGNAL);
}

void process_request(int fd, int i) {
	static char Buffer[1024];
	int RecvResult = recv(fd, Buffer, 1024, MSG_NOSIGNAL);
	if ((RecvResult == 0) && (errno != EAGAIN)) {
		shutdown(fd, SHUT_RDWR);
	} else if (RecvResult > 0) {
		//send(fd, Buffer, RecvResult, MSG_NOSIGNAL);
		std::istringstream is(Buffer);
		std::string part;
		while(std::getline(is, part, '\n')) {
			std::cout << "part: " << part << std::endl;
			if (part.find("GET") == 0) {
				std::cout << "GET REQUEST" << std::endl;
				size_t begin = part.find('/');
				size_t end = part.find_first_of("? ", begin);
				std::string path = part.substr(begin, end-begin);
				path = "." + path;
				std::cout << "Path: " << path << std::endl;
				if (is_regular_file(path.c_str())) {
					sendFile(fd, readFile(path));
				} else {
					send404(fd);
					std::cout << "404" << std::endl;
				}
				/*
				std::string filename = "." + path;
				std::ifstream requested_file(filename.c_str());
				if (is_regular_file(path.c_str())) {
					std::cout << "200" << std::endl;
					std::cout << "file: {" << requested_file.rdbuf() << "}" << std::endl;
					const char * OK = "HTTP/1.1 200 OK\r\n";
					const char * content_type = "Content-Type: text/html\r\n";
					std::string len_h("Content-Length: ");
					requested_file.seekg(0, requested_file.end);
					int f_len = requested_file.tellg();
					requested_file.seekg(0, requested_file.beg);
					std::string len = len_h + std::to_string(f_len) + "\r\n";
					std::cout << "len = " << f_len << std::endl;
					std::stringstream s;
					s << requested_file.rdbuf();

					send(fd, OK, strlen(OK), MSG_NOSIGNAL);
					send(fd, content_type, strlen(content_type), MSG_NOSIGNAL);
					send(fd, len.c_str(), len.length(), MSG_NOSIGNAL);
					send(fd, "\r\n", 2, MSG_NOSIGNAL);
					int res = send(fd, s.str().c_str(), f_len, MSG_NOSIGNAL);
					//std::cout <<"Send = " << requested_file.rdbuf() << std::endl;
				} else{
					std::cout << "404" << std::endl;
				}
				requested_file.close();
				*/

			}
		}
	}
}

int main(int argc, char * argv[])
{

	char * addr, *port;
	char * dir = ".";

	int c;
	while ((c = getopt (argc, argv, "h:p:d:")) != -1)
	{
		switch (c)
		{
			case 'h':
				addr = strdup(optarg);
				break;
			case 'p':
				port = strdup(optarg);
				break;
			case 'd':
				dir = strdup(optarg);
				break;
			default:
				exit(0);
		}

	}

	chdir(dir);
	daemonize();
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
				process_request(Events[i].data.fd, i);
				close(Events[i].data.fd);
			}
		}
	}
	return 0;
}
