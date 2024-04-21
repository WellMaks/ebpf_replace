// #include <sys/syscall.h>
// #include <unistd.h>

// int main(void) {
//     int fd = syscall(SYS_open, "/etc/passwd", 0);


//     char buffer[1024]; 
//     int bytes;

//     bytes = syscall(SYS_read, fd, buffer, sizeof(buffer) - 1);


//     syscall(SYS_write, 1, buffer, bytes);
   

//     syscall(SYS_close, fd);
//     return 0;
// }

#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    int fd = syscall(SYS_open, "/etc/passwd", 0);

    char buffer[1024];
    int bytes;

    bytes = syscall(SYS_read, fd, buffer, sizeof(buffer) - 1);

    const char *message = "fuck you \n";
    int message_len = 11; // Length of the message "fuck you"

    for (int i = 0; i < message_len; ++i) {
        buffer[i] = message[i];
    }

    syscall(SYS_write, 1, buffer, message_len);

    syscall(SYS_close, fd);
    return 0;
}