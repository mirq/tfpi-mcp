/* The a314.device interface tfdbgd uses (see a314device/a314.h in a314). */
#ifndef TFDBGD_A314_H
#define TFDBGD_A314_H

#include <exec/io.h>

#define A314_NAME               "a314.device"

#define A314_CONNECT            (CMD_NONSTD + 0)
#define A314_READ               (CMD_NONSTD + 1)
#define A314_WRITE              (CMD_NONSTD + 2)
#define A314_EOS                (CMD_NONSTD + 3)
#define A314_RESET              (CMD_NONSTD + 4)

#define A314_CONNECT_OK         0
#define A314_READ_OK            0
#define A314_WRITE_OK           0

struct A314_IORequest {
    struct IORequest a314_Request;
    ULONG a314_Socket;
    STRPTR a314_Buffer;
    WORD a314_Length;
};

#endif
