#ifndef __KITESHIELD_OBFUSCATED_STRINGS_H
#define __KITESHIELD_OBFUSCATED_STRINGS_H

#define DEOBF_STR(str)                                                         \
  ({ volatile char cleartext[sizeof(str)];                                     \
     for (int i = 0; i < sizeof(str); i++) {                                   \
       cleartext[i] = str[i] ^ ((0x83 + i) % 256);                             \
     };                                                                        \
     cleartext[sizeof(cleartext) - 1] = '\0';                                 \
     (char *) cleartext; })


/* "/proc/%d/status" */
static const char PROC_STATUS_FMT[] = "\xac\xf4\xf7\xe9\xe4\xa7\xac\xee\xa4\xff\xf9\xef\xfb\xe5\xe2";

/* "TracerPid:" */
static const char TRACERPID_PROC_FIELD[] = "\xd7\xf6\xe4\xe5\xe2\xfa\xd9\xe3\xef\xb6";

/* "/proc/%d/stat" */
static const char PROC_STAT_FMT[] = "\xac\xf4\xf7\xe9\xe4\xa7\xac\xee\xa4\xff\xf9\xef\xfb";

/* "LD_PRELOAD" */
static const char LD_PRELOAD[] = "\xcf\xc0\xda\xd6\xd5\xcd\xc5\xc5\xca\xc8";

/* "LD_AUDIT" */
static const char LD_AUDIT[] = "\xcf\xc0\xda\xc7\xd2\xcc\xc0\xde";

/* "LD_DEBUG" */
static const char LD_DEBUG[] = "\xcf\xc0\xda\xc2\xc2\xca\xdc\xcd";

/* "0123456789abcdef" */
static const char HEX_DIGITS[] = "\xb3\xb5\xb7\xb5\xb3\xbd\xbf\xbd\xb3\xb5\xec\xec\xec\xf4\xf4\xf4";


#endif /* __KITESHIELD_OBFUSCATED_STRINGS_H */
