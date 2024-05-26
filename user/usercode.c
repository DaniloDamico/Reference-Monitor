#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define STATE_FILE "/sys/module/reference_monitor/parameters/state_char"
#define CURRSTATE "currstate"
#define LISTPROTECTED "listprotected"
#define LISTPROTECTED_FILE "/proc/rm_protected"
#define LOG "log"
#define LOG_FILE "/mnt/mountfs/logfile"

void print_file(char* filepath){
    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
        perror("Can't find resource");
        return;
    }

    char ch;
    while ((ch = fgetc(file)) != EOF) {
        putchar(ch);
    }

    if (ferror(file)) {
        perror("Error reading resource");
    }

    fclose(file);
}

int main() {
    char userInput[500] = {0};
    int fd;
    int ret;
    
    if (seteuid(0) == -1) {
        perror("seteuid");
        return 1;
    }

    printf("use this program to communicate with the Reference Monitor\n");
    printf("the default password is \"passw\" and will be used in the following examples\n");
    printf("Usage:\n");
    printf("\tpassw changepassw \"newpassw\"\n");
    printf("\tpassw setstate \"REC_ON\"\n");
    printf("\tpassw addpath \"/absolute/path\"\n");
    printf("\tpassw removepath \"/absolute/path\"\n");
    printf("\tpassw uninstall\n");
    printf("\tcurrstate\n");
    printf("\tlistprotected\n");
    printf("\tlog\n");
    
    printf("You can only add or remove paths in REC_OFF or REC_ON state.\n");
    printf("You can add or remove directories but be sure they end in \"/\".\n");
    printf("Uninstall removes the reference count the module calls to prevent rmmod from working.\n");
    printf("\n");
    
    while(1){
        printf("> ");
        if(!fgets(userInput, sizeof(userInput), stdin)) continue;

        if(userInput[0]=='\n') continue;
        userInput[strlen(userInput)-1] = '\0'; // replaces newline with terminator

        if (strcmp(userInput, CURRSTATE) == 0) {
            print_file(STATE_FILE);
            continue;
        }
                
        if (strcmp(userInput, LISTPROTECTED) == 0) {
            print_file(LISTPROTECTED_FILE);
            printf("\n");
            continue;
        }

        if (strcmp(userInput, LOG) == 0) {
            print_file(LOG_FILE);
            printf("\n");
            continue;
        }

        fd = open("/proc/rm_config", O_WRONLY);
        if (fd <= 0) {
            printf("Error opening proc file.\n");
            return 1;
        }
        
        ret = write(fd, userInput, strlen(userInput));
        close(fd);

        switch (ret) {
            case 1:
                printf("error: bad euid\n");
                break;
            case 2:
                printf("error acquiring command\n");
                break;
            case 3:
                printf("wrong password\n");
                break;
            case 4:
                printf("invalid parameter\n");
                break;
            case 5:
                printf("module not in a reconfigurable state\n");
                break;
            case 6:
                printf("invalid command\n");
                break;
            default:
                break;
        }
    }
}
