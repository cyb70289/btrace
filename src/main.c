#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int record_main(int argc, char **argv);
int report_main(int argc, char **argv);

static void usage(void) {
    fprintf(stderr, "btrace - profile thread block/wakeup relationships\n"
                    "\n"
                    "Usage:\n"
                    "  btrace record -p <PID> [-d <depth>] [-o <file>]\n"
                    "  btrace report -i <file> [-o <dir>] [--dot]\n"
                    "\n"
                    "Commands:\n"
                    "  record   Profile a process and save results to a file\n"
                    "  report   Analyze saved data and show insights\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage();
        return 1;
    }

    if (strcmp(argv[1], "record") == 0)
        return record_main(argc - 1, argv + 1);
    if (strcmp(argv[1], "report") == 0)
        return report_main(argc - 1, argv + 1);

    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    usage();
    return 1;
}
