/* Memory, task/library/memory lists, signals, files. */

#include <exec/types.h>
#include <exec/memory.h>
#include <exec/execbase.h>
#include <dos/dos.h>
#include <dos/dosextens.h>

#include <proto/exec.h>
#include <proto/dos.h>

#include <string.h>

#include "tfdbgd.h"

/* copy with the agent's trap handler armed: a bus/address error returns -1 */
LONG probe_copy(void *src, void *dst, ULONG len, ULONG width)
{
    agent_job.probe_faulted = 0;
    agent_job.probing = 1;
    LONG r = tfdbg_probe_copy(src, dst, len, width);
    agent_job.probing = 0;
    return r || agent_job.probe_faulted ? -1 : 0;
}

static BOOL width_ok(ULONG addr, ULONG len, UBYTE width)
{
    if (width != 1 && width != 2 && width != 4)
        return FALSE;
    return (addr % width) == 0 && (len % width) == 0;
}

/* u32 addr, u32 len, u8 width, u8 flags (1 force) -> data */
UBYTE rq_mem_read(struct Rd *r, struct Buf *out)
{
    ULONG addr = rd_u32(r), len = rd_u32(r);
    UBYTE width = rd_u8(r), flags = rd_u8(r);
    if (r->bad || len > MAX_CHUNK || !width_ok(addr, len, width))
        return ST_BAD_REQUEST;
    LONG st = addr_check(addr, len, FALSE, flags & 1);
    if (st)
        return st;
    UBYTE *dst = buf_reserve(out, len);
    if (!dst)
        return ST_NO_MEMORY;
    if (probe_copy((void *)addr, dst, len, width))
        return ST_BUS_ERROR;
    return ST_OK;
}

/* u32 addr, u8 width, u8 flags (1 force), u16 pad, data */
UBYTE rq_mem_write(struct Rd *r, struct Buf *out)
{
    (void)out;
    ULONG addr = rd_u32(r);
    UBYTE width = rd_u8(r), flags = rd_u8(r);
    rd_u16(r);
    ULONG len = r->left;
    if (r->bad || !len || !width_ok(addr, len, width))
        return ST_BAD_REQUEST;
    LONG st = addr_check(addr, len, TRUE, flags & 1);
    if (st)
        return st;
    if (probe_copy((void *)r->p, (void *)addr, len, width))
        return ST_BUS_ERROR;
    r->left = 0;
    CacheClearU();
    return ST_OK;
}

static BOOL readable(const void *p)
{
    ULONG a = (ULONG)p;
    return a && (TypeOfMem((APTR)p) || (a >= 0xF80000 && a <= 0xFFFFFF) || (a >= 0xE00000 && a <= 0xE7FFFF));
}

static void put_cstr(struct Buf *b, const char *s)
{
    if (!readable(s)) {
        buf_u16(b, 0);
        return;
    }
    ULONG n = 0;
    while (n < 80 && s[n] && s[n] != '\r' && s[n] != '\n')
        n++;
    buf_u16(b, n);
    buf_bytes(b, s, n);
}

static void put_task(struct Buf *b, struct Task *t)
{
    buf_u32(b, (ULONG)t);
    buf_u8(b, t->tc_Node.ln_Pri);
    buf_u8(b, t->tc_State);
    buf_u8(b, t->tc_Node.ln_Type);
    buf_u8(b, 0);
    buf_u32(b, t->tc_SigWait);
    buf_u32(b, t->tc_SigRecvd);
    buf_u32(b, (ULONG)t->tc_SPReg);
    buf_u32(b, (ULONG)t->tc_SPLower);
    buf_u32(b, (ULONG)t->tc_SPUpper);
    UWORD cli = 0;
    struct CommandLineInterface *c = NULL;
    if (t->tc_Node.ln_Type == NT_PROCESS) {
        struct Process *p = (struct Process *)t;
        cli = p->pr_TaskNum;
        if (p->pr_CLI)
            c = BADDR(p->pr_CLI);
    }
    buf_u16(b, cli);
    put_cstr(b, t->tc_Node.ln_Name);
    UBYTE *cmd = c ? BADDR(c->cli_CommandName) : NULL;
    if (cmd && readable(cmd)) {
        UBYTE n = cmd[0] > 80 ? 80 : cmd[0];
        buf_u16(b, n);
        buf_bytes(b, cmd + 1, n);
    } else
        buf_u16(b, 0);
}

/* -> u16 n, n x task (see put_task) */
UBYTE rq_tasks(struct Rd *r, struct Buf *out)
{
    (void)r;
    /* reserve up front: no allocations while interrupts are off.
       Worst case per task: 32 fixed + 2 x (2 + 80) bytes; at most 250 tasks. */
    if (!buf_reserve(out, 2 + 250 * 200))
        return ST_NO_MEMORY;
    out->len = 0;
    buf_u16(out, 0);
    UWORD n = 0;
    Disable();
    put_task(out, SysBase->ThisTask);
    n++;
    struct List *lists[2] = { &SysBase->TaskReady, &SysBase->TaskWait };
    for (int i = 0; i < 2; i++)
        for (struct Node *nd = lists[i]->lh_Head; nd->ln_Succ && n < 250; nd = nd->ln_Succ) {
            put_task(out, (struct Task *)nd);
            n++;
        }
    Enable();
    out->data[0] = n >> 8;
    out->data[1] = n;
    return ST_OK;
}

/* check and signal in one protected window: the task can't go away between */
BOOL signal_task(struct Task *t, ULONG mask)
{
    BOOL found = FALSE;
    Disable();
    if (t == SysBase->ThisTask)
        found = TRUE;
    struct List *lists[2] = { &SysBase->TaskReady, &SysBase->TaskWait };
    for (int i = 0; i < 2 && !found; i++)
        for (struct Node *nd = lists[i]->lh_Head; nd->ln_Succ; nd = nd->ln_Succ)
            if ((struct Task *)nd == t)
                found = TRUE;
    if (found)
        Signal(t, mask);
    Enable();
    return found;
}

/* u8 kind (0 libraries, 1 devices, 2 resources, 3 ports, 4 semaphores)
 * -> u16 n, n x (u32 addr, u16 version, u16 revision, u16 opencnt, u8 type, i8 pri, str name, str extra) */
UBYTE rq_libs(struct Rd *r, struct Buf *out)
{
    UBYTE kind = rd_u8(r);
    if (r->bad || kind > 4)
        return ST_BAD_REQUEST;
    /* at most 400 nodes x (16 fixed + 2 x 82 bytes): no allocations in Forbid */
    struct List *lists[5] = { &SysBase->LibList, &SysBase->DeviceList, &SysBase->ResourceList,
                              &SysBase->PortList, &SysBase->SemaphoreList };
    if (!buf_reserve(out, 2 + 400 * 180))
        return ST_NO_MEMORY;
    out->len = 0;
    buf_u16(out, 0);
    UWORD n = 0;
    Forbid();
    for (struct Node *nd = lists[kind]->lh_Head; nd->ln_Succ && n < 400; nd = nd->ln_Succ, n++) {
        buf_u32(out, (ULONG)nd);
        if (kind <= 2) {
            struct Library *l = (struct Library *)nd;
            buf_u16(out, l->lib_Version);
            buf_u16(out, l->lib_Revision);
            buf_u16(out, l->lib_OpenCnt);
        } else {
            buf_u16(out, 0);
            buf_u16(out, 0);
            buf_u16(out, 0);
        }
        buf_u8(out, nd->ln_Type);
        buf_u8(out, nd->ln_Pri);
        put_cstr(out, nd->ln_Name);
        if (kind < 2)
            put_cstr(out, ((struct Library *)nd)->lib_IdString);
        else if (kind == 3) {
            struct MsgPort *mp = (struct MsgPort *)nd;
            struct Task *t = mp->mp_SigTask;
            put_cstr(out, (mp->mp_Flags & PF_ACTION) == PA_SIGNAL && readable(t) ? t->tc_Node.ln_Name : NULL);
        } else
            buf_u16(out, 0);
    }
    Permit();
    out->data[0] = n >> 8;
    out->data[1] = n;
    return ST_OK;
}

/* -> 7 x u32 (avail chip, fast, any, largest chip, largest fast, total chip, total fast),
 *    u16 n, n x (u32 lower, u32 upper, u32 free, u16 attributes, i8 pri, u8 pad, str name) */
UBYTE rq_memstats(struct Rd *r, struct Buf *out)
{
    (void)r;
    buf_u32(out, AvailMem(MEMF_CHIP));
    buf_u32(out, AvailMem(MEMF_FAST));
    buf_u32(out, AvailMem(MEMF_ANY));
    buf_u32(out, AvailMem(MEMF_CHIP | MEMF_LARGEST));
    buf_u32(out, AvailMem(MEMF_FAST | MEMF_LARGEST));
    buf_u32(out, AvailMem(MEMF_CHIP | MEMF_TOTAL));
    buf_u32(out, AvailMem(MEMF_FAST | MEMF_TOTAL));
    if (!buf_reserve(out, 4096))
        return ST_NO_MEMORY;
    out->len -= 4096;
    ULONG at = out->len;
    buf_u16(out, 0);
    UWORD n = 0;
    Forbid();
    for (struct Node *nd = SysBase->MemList.lh_Head; nd->ln_Succ && n < 32; nd = nd->ln_Succ, n++) {
        struct MemHeader *mh = (struct MemHeader *)nd;
        buf_u32(out, (ULONG)mh->mh_Lower);
        buf_u32(out, (ULONG)mh->mh_Upper);
        buf_u32(out, mh->mh_Free);
        buf_u16(out, mh->mh_Attributes);
        buf_u8(out, nd->ln_Pri);
        buf_u8(out, 0);
        put_cstr(out, nd->ln_Name);
    }
    Permit();
    out->data[at] = n >> 8;
    out->data[at + 1] = n;
    return ST_OK;
}

/* u32 task, u32 mask: Ctrl-C..F only */
UBYTE rq_signal(struct Rd *r, struct Buf *out)
{
    (void)out;
    struct Task *t = (struct Task *)rd_u32(r);
    ULONG mask = rd_u32(r);
    if (r->bad)
        return ST_BAD_REQUEST;
    mask &= SIGBREAKF_CTRL_C | SIGBREAKF_CTRL_D | SIGBREAKF_CTRL_E | SIGBREAKF_CTRL_F;
    if (!mask)
        return ST_BAD_REQUEST;
    return signal_task(t, mask) ? ST_OK : ST_BAD_ADDRESS;
}

/* str path, u32 offset, u32 len -> u32 size, data */
UBYTE rq_file_read(struct Rd *r, struct Buf *out)
{
    STRPTR path = rd_str(r);
    ULONG offset = rd_u32(r), len = rd_u32(r);
    if (r->bad || !path) {
        if (path) FreeVec(path);
        return ST_BAD_REQUEST;
    }
    if (len > MAX_CHUNK)
        len = MAX_CHUNK;
    BPTR fh = Open(path, MODE_OLDFILE);
    FreeVec(path);
    if (!fh) {
        buf_u32(out, IoErr());
        return ST_DOS_ERROR;
    }
    Seek(fh, 0, OFFSET_END);
    LONG size = Seek(fh, 0, OFFSET_BEGINNING);
    buf_u32(out, size < 0 ? 0 : size);
    if (offset && Seek(fh, offset, OFFSET_BEGINNING) < 0) {
        len = 0;
    }
    UBYTE *dst = len ? buf_reserve(out, len) : NULL;
    if (len && !dst) {
        Close(fh);
        return ST_NO_MEMORY;
    }
    LONG got = len ? Read(fh, dst, len) : 0;
    Close(fh);
    if (got < 0)
        got = 0;
    out->len -= len - got;
    return ST_OK;
}
