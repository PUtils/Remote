#include "rt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Seatbelt rules; the last matching rule wins. Everything is readable except
 * the real home directory; nothing is writable except the working directory,
 * the sandbox home, temp dirs and /dev. Tool directories found on PATH inside
 * home are re-allowed for reading so installed tools keep working.
 */
static const char head[] =
    "(version 1)\n"
    "(allow default)\n"
    "(deny file-read-data file-read-xattr file-write* (subpath (param \"HOME\")))\n"
    "(deny file-write*)\n"
    "(allow file-write* (subpath \"/dev\") (subpath \"/private/tmp\")"
    " (subpath \"/private/var/folders\"))\n";

static const char tail[] =
    "(allow file-read-data file-read-xattr file-write* (subpath (param \"DIR\")))\n"
    "(deny file-read-data file-read-xattr file-write* (subpath (param \"STATE\")))\n"
    "(allow file-read-data file-read-xattr file-write* (subpath (param \"SBHOME\")))\n"
    "(deny mach-lookup (global-name \"com.apple.SecurityServer\")"
    " (global-name \"com.apple.securityd.xpc\"))\n"
    /* Each of these would run code outside the sandbox. */
    "(deny job-creation lsopen appleevent-send)\n";

int sandbox_tools(const char *home, char tools[][PATH_MAX], int max)
{
    const char *path = getenv("PATH");
    size_t hl = strlen(home);
    int n = 0;
    if (!path)
        return 0;
    char *copy = strdup(path), *save = NULL;
    for (char *d = strtok_r(copy, ":", &save); d && n < max; d = strtok_r(NULL, ":", &save)) {
        char real[PATH_MAX];
        if (!realpath(d, real) || strncmp(real, home, hl) != 0 || real[hl] != '/')
            continue;
        /* Allow the directory above bin/ so a tool's own lib/ and share/ resolve. */
        char *slash = strrchr(real, '/');
        if (slash && (size_t)(slash - real) > hl)
            *slash = '\0';
        int dup = 0;
        for (int i = 0; i < n; i++)
            dup |= strcmp(tools[i], real) == 0;
        if (!dup)
            strlcpy(tools[n++], real, PATH_MAX);
    }
    free(copy);
    return n;
}

int sandbox_profile(char *out, size_t cap, int ntools)
{
    size_t len = strlcpy(out, head, cap);
    for (int i = 0; i < ntools && len < cap; i++)
        len += snprintf(out + len, cap - len,
                        "(allow file-read-data file-read-xattr (subpath (param \"T%d\")))\n", i);
    if (len < cap)
        len += strlcpy(out + len, tail, cap - len);
    return len < cap ? 0 : -1;
}
