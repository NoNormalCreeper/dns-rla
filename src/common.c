#include "common.h"

#include <ctype.h>

void normalize_domain(char* domain) {
    for (; *domain != '\0'; domain++) {
        *domain = (char)tolower((unsigned char)*domain);
    }
}
