#include <stdio.h>
#include <string.h>

void build_label(const char *user_input) {
    char label[64];
    strcpy(label, user_input);
    printf(label);
}

int main(int argc, char **argv) {
    char buf[128];
    sprintf(buf, "order-%s", argv[1]);
    build_label(buf);
    return 0;
}
