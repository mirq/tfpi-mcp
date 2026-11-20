/* Keyboard and mouse events into input.device (what Intuition and
 * system-friendly programs see; games that read the hardware won't). */

#include <exec/types.h>
#include <exec/memory.h>
#include <devices/input.h>
#include <devices/inputevent.h>

#include <proto/exec.h>
#include <proto/intuition.h>

#include "tfdbgd.h"

static struct MsgPort *input_mp;
static struct IOStdReq *input_io;

static BOOL open_input(void)
{
    if (input_io)
        return TRUE;
    input_mp = CreateMsgPort();
    if (!input_mp)
        return FALSE;
    input_io = (struct IOStdReq *)CreateIORequest(input_mp, sizeof(struct IOStdReq));
    if (input_io && !OpenDevice("input.device", 0, (struct IORequest *)input_io, 0))
        return TRUE;
    if (input_io)
        DeleteIORequest((struct IORequest *)input_io);
    input_io = NULL;
    DeleteMsgPort(input_mp);
    input_mp = NULL;
    return FALSE;
}

void input_cleanup(void)
{
    if (input_io) {
        CloseDevice((struct IORequest *)input_io);
        DeleteIORequest((struct IORequest *)input_io);
        DeleteMsgPort(input_mp);
    }
    input_io = NULL;
    input_mp = NULL;
}

/* u8 n, n x (u8 class (1 rawkey, 2 rawmouse), u8 pad, u16 code, u16 qualifier, i16 x, i16 y) */
UBYTE rq_input(struct Rd *r, struct Buf *out)
{
    (void)out;
    UBYTE n = rd_u8(r);
    if (r->bad || n == 0 || r->left < (ULONG)n * 10)
        return ST_BAD_REQUEST;
    if (readonly)
        return ST_DENIED;
    if (!open_input())
        return ST_UNSUPPORTED;
    for (UBYTE i = 0; i < n; i++) {
        UBYTE cls = rd_u8(r);
        rd_u8(r);
        struct InputEvent ie = { 0 };
        ie.ie_Class = cls == 2 ? IECLASS_RAWMOUSE : IECLASS_RAWKEY;
        ie.ie_Code = rd_u16(r);
        ie.ie_Qualifier = rd_u16(r);
        ie.ie_X = (WORD)rd_u16(r);
        ie.ie_Y = (WORD)rd_u16(r);
        if (cls == 2)
            ie.ie_Qualifier |= IEQUALIFIER_RELATIVEMOUSE;
        ULONG secs, micros;
        CurrentTime(&secs, &micros);
        ie.ie_TimeStamp.tv_secs = secs;
        ie.ie_TimeStamp.tv_micro = micros;
        input_io->io_Command = IND_WRITEEVENT;
        input_io->io_Data = &ie;
        input_io->io_Length = sizeof(ie);
        input_io->io_Flags = 0;
        DoIO((struct IORequest *)input_io);
    }
    return ST_OK;
}
