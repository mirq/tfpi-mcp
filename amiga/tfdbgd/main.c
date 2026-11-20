/*
 * tfdbgd - tfpi-mcp's agent on the Amiga.
 *
 *   run >NIL: PI0:.tfmcp/tfdbgd [READONLY] [NOREBOOT]
 *
 * Connects to the "tfdbg" a314 service on the Pi (the tfpi-mcp bridge) and
 * serves its requests until Ctrl-C (refused while jobs are running) or QUIT.
 * READONLY refuses memory writes, register changes and input events;
 * NOREBOOT refuses the reboot request. Needs a 68020 or better.
 */

#include <exec/types.h>
#include <exec/memory.h>
#include <exec/execbase.h>
#include <libraries/configvars.h>
#include <libraries/expansion.h>
#include <dos/dos.h>
#include <dos/rdargs.h>

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/expansion.h>
#include <proto/alib.h>

#include <string.h>

#include "a314.h"
#include "tfdbgd.h"

struct ExpansionBase *ExpansionBase;

struct MsgPort *agent_port;
struct Job agent_job;
BOOL readonly;
BOOL noreboot;

static struct MsgPort *sync_mp, *async_mp;
static struct A314_IORequest *sync_ior, *read_ior;
static ULONG a314_socket;
static BOOL connected, pending_read, quit;
static APTR old_trapdata;
static UBYTE read_buf[224];

/* incoming frame assembly */
static UBYTE hdr[4];
static ULONG hdr_have;
static UBYTE *req;
static ULONG req_len, req_have;

#define WRITE_CHUNK 224

/* ---- buffers --------------------------------------------------------- */

void buf_init(struct Buf *b) { b->data = NULL; b->len = b->cap = 0; b->failed = FALSE; }

void buf_free(struct Buf *b)
{
    if (b->data)
        FreeVec(b->data);
    buf_init(b);
}

UBYTE *buf_reserve(struct Buf *b, ULONG n)
{
    if (b->failed)
        return NULL;
    if (b->len + n > b->cap) {
        ULONG cap = b->cap ? b->cap : 256;
        while (cap < b->len + n)
            cap *= 2;
        UBYTE *d = AllocVec(cap, MEMF_ANY);
        if (!d) {
            b->failed = TRUE;
            return NULL;
        }
        if (b->data) {
            CopyMem(b->data, d, b->len);
            FreeVec(b->data);
        }
        b->data = d;
        b->cap = cap;
    }
    UBYTE *p = b->data + b->len;
    b->len += n;
    return p;
}

void buf_bytes(struct Buf *b, const void *p, ULONG n)
{
    UBYTE *d = buf_reserve(b, n);
    if (d && n)
        CopyMem((APTR)p, d, n);
}

void buf_u8(struct Buf *b, UBYTE v) { buf_bytes(b, &v, 1); }
void buf_u16(struct Buf *b, UWORD v) { buf_bytes(b, &v, 2); }   /* 68k: big-endian */
void buf_u32(struct Buf *b, ULONG v) { buf_bytes(b, &v, 4); }

void buf_str(struct Buf *b, const char *s)
{
    ULONG n = s ? strlen(s) : 0;
    if (n > 255)
        n = 255;
    buf_u16(b, n);
    buf_bytes(b, s, n);
}

void buf_bstr(struct Buf *b, BSTR s)
{
    UBYTE *p = BADDR(s);
    if (!p) {
        buf_u16(b, 0);
        return;
    }
    buf_u16(b, p[0]);
    buf_bytes(b, p + 1, p[0]);
}

UBYTE rd_u8(struct Rd *r)
{
    if (r->left < 1) { r->bad = TRUE; return 0; }
    r->left--;
    return *r->p++;
}

UWORD rd_u16(struct Rd *r)
{
    UWORD hi = rd_u8(r);
    return (hi << 8) | rd_u8(r);
}

ULONG rd_u32(struct Rd *r)
{
    ULONG hi = rd_u16(r);
    return (hi << 16) | rd_u16(r);
}

STRPTR rd_str(struct Rd *r)
{
    UWORD n = rd_u16(r);
    if (r->bad || n > r->left) {
        r->bad = TRUE;
        return NULL;
    }
    STRPTR s = AllocVec(n + 1, MEMF_ANY | MEMF_CLEAR);
    if (!s)
        return NULL;
    CopyMem((APTR)r->p, s, n);
    r->p += n;
    r->left -= n;
    return s;
}

/* ---- a314 ------------------------------------------------------------- */

static BYTE a314_cmd(struct A314_IORequest *ior, struct MsgPort *mp, UWORD cmd, void *buffer, WORD length)
{
    ior->a314_Request.io_Message.mn_ReplyPort = mp;
    ior->a314_Request.io_Command = cmd;
    ior->a314_Request.io_Error = 0;
    ior->a314_Socket = a314_socket;
    ior->a314_Buffer = buffer;
    ior->a314_Length = length;
    return DoIO((struct IORequest *)ior);
}

static void a314_write(const UBYTE *p, ULONG n)
{
    while (n && connected) {
        WORD k = n > WRITE_CHUNK ? WRITE_CHUNK : n;
        if (a314_cmd(sync_ior, sync_mp, A314_WRITE, (void *)p, k) != A314_WRITE_OK) {
            connected = FALSE;
            return;
        }
        p += k;
        n -= k;
    }
}

static void send_frame(UBYTE type, UBYTE status, ULONG id, struct Buf *payload)
{
    if (!connected)
        return;
    ULONG plen = payload && !payload->failed ? payload->len : 0;
    if (payload && payload->failed)
        status = ST_NO_MEMORY;
    UBYTE h[HDR_LEN];
    ULONG len = 8 + plen;
    h[0] = len >> 24; h[1] = len >> 16; h[2] = len >> 8; h[3] = len;
    h[4] = type; h[5] = status; h[6] = 0; h[7] = 0;
    h[8] = id >> 24; h[9] = id >> 16; h[10] = id >> 8; h[11] = id;
    a314_write(h, HDR_LEN);
    if (plen)
        a314_write(payload->data, plen);
}

void send_event(UBYTE type, struct Buf *b)
{
    send_frame(type, ST_OK, 0, b);
}

static void start_read(void)
{
    read_ior->a314_Request.io_Message.mn_ReplyPort = async_mp;
    read_ior->a314_Request.io_Command = A314_READ;
    read_ior->a314_Request.io_Error = 0;
    read_ior->a314_Socket = a314_socket;
    read_ior->a314_Buffer = read_buf;
    read_ior->a314_Length = sizeof(read_buf);
    SendIO((struct IORequest *)read_ior);
    pending_read = TRUE;
}

/* ---- memory ranges ------------------------------------------------------- */

/* 0 ok, else ST_BAD_ADDRESS / ST_DENIED */
LONG addr_check(ULONG addr, ULONG len, BOOL write, BOOL force)
{
    if (len == 0)
        return ST_OK;
    ULONG last = addr + len - 1;
    if (last < addr)
        return ST_BAD_ADDRESS;
    if (write && readonly)
        return ST_DENIED;
    if (force)
        return ST_OK;
    if (TypeOfMem((APTR)addr) && TypeOfMem((APTR)last))
        return ST_OK;
    if (write)
        return ST_BAD_ADDRESS;     /* outside RAM needs force */
    if (addr >= 0xF80000 && last <= 0xFFFFFF)
        return ST_OK;              /* Kickstart ROM */
    if (addr >= 0xE00000 && last <= 0xE7FFFF)
        return ST_OK;              /* extended ROM */
    if (ExpansionBase) {
        struct ConfigDev *cd = NULL;
        while ((cd = FindConfigDev(cd, -1, -1))) {
            ULONG lo = (ULONG)cd->cd_BoardAddr, hi = lo + cd->cd_BoardSize - 1;
            if ((cd->cd_Rom.er_Type & ERTF_MEMLIST) && addr >= lo && last <= hi)
                return ST_OK;      /* memory board (e.g. RTG RAM); I/O boards need force */
        }
    }
    return ST_BAD_ADDRESS;
}

/* ---- requests ------------------------------------------------------------- */

static UBYTE rq_hello(struct Rd *r, struct Buf *out)
{
    (void)r;
    buf_u16(out, PROTO_VERSION);
    buf_u16(out, AGENT_VERSION);
    buf_u16(out, SysBase->AttnFlags);
    buf_u16(out, SysBase->LibNode.lib_Version);
    buf_u16(out, SysBase->LibNode.lib_Revision);
    buf_u16(out, SysBase->SoftVer);
    buf_u32(out, AvailMem(MEMF_CHIP));
    buf_u32(out, AvailMem(MEMF_FAST));
    buf_u32(out, (ULONG)FindTask(NULL));
    ULONG flags = 0;
    if (readonly) flags |= 1;
    if (noreboot) flags |= 2;
    buf_u32(out, flags);
    buf_u8(out, SysBase->VBlankFrequency);
    buf_u8(out, SysBase->PowerSupplyFrequency);
    return ST_OK;
}

static UBYTE rq_reboot(struct Rd *r, struct Buf *out)
{
    (void)r; (void)out;
    if (noreboot || readonly)
        return ST_DENIED;
    ColdReboot();
    return ST_OK;   /* not reached */
}

static UBYTE rq_quit(struct Rd *r, struct Buf *out)
{
    (void)r; (void)out;
    if (jobs_running())
        return ST_BUSY;
    quit = TRUE;
    return ST_OK;
}

typedef UBYTE (*handler_t)(struct Rd *, struct Buf *);

static const handler_t handlers[] = {
    NULL,
    rq_hello, rq_mem_read, rq_mem_write, rq_tasks, rq_libs, rq_memstats, rq_signal,
    rq_run, rq_jobs, rq_bp, rq_cont, rq_regs, rq_setreg, rq_screens, rq_grab,
    rq_input, rq_reboot, rq_segs, rq_job_break, rq_quit, rq_file_read,
};

static void handle_request(UBYTE *p, ULONG n)
{
    if (n < 8)
        return;
    UBYTE type = p[0];
    ULONG id = ((ULONG)p[4] << 24) | ((ULONG)p[5] << 16) | ((ULONG)p[6] << 8) | p[7];
    struct Rd rd = { p + 8, n - 8, FALSE };
    struct Buf out;
    buf_init(&out);
    UBYTE status = ST_UNSUPPORTED;
    if (quit) {
        status = ST_BUSY;           /* quitting: nothing new may start */
    } else if (type < sizeof(handlers) / sizeof(handlers[0]) && handlers[type]) {
        status = handlers[type](&rd, &out);
        if (rd.bad && status == ST_OK)
            status = ST_BAD_REQUEST;
    }
    if (status != ST_OK && status != ST_DOS_ERROR)
        out.len = 0;
    send_frame(type, status, id, &out);
    buf_free(&out);
}

static void reset_frame(void)
{
    if (req)
        FreeVec(req);
    req = NULL;
    hdr_have = req_have = req_len = 0;
}

static void consume(UBYTE *p, ULONG n)
{
    while (n && connected && !quit) {
        if (hdr_have < 4) {
            hdr[hdr_have++] = *p++;
            n--;
            if (hdr_have == 4) {
                req_len = ((ULONG)hdr[0] << 24) | ((ULONG)hdr[1] << 16) | ((ULONG)hdr[2] << 8) | hdr[3];
                if (req_len < 8 || req_len > MAX_REQUEST || !(req = AllocVec(req_len, MEMF_ANY))) {
                    a314_cmd(sync_ior, sync_mp, A314_RESET, NULL, 0);
                    connected = FALSE;
                    reset_frame();
                    return;
                }
                req_have = 0;
            }
        } else {
            ULONG k = req_len - req_have;
            if (k > n)
                k = n;
            CopyMem(p, req + req_have, k);
            req_have += k;
            p += k;
            n -= k;
            if (req_have == req_len) {
                UBYTE *q = req;
                ULONG ql = req_len;
                req = NULL;
                hdr_have = 0;
                handle_request(q, ql);
                FreeVec(q);
            }
        }
    }
}

static void handle_read_done(void)
{
    pending_read = FALSE;
    if (!connected)
        return;
    if (read_ior->a314_Request.io_Error == A314_READ_OK) {
        consume(read_ior->a314_Buffer, read_ior->a314_Length);
        if (connected)
            start_read();
    } else {
        /* EOS or reset from the Pi: tear the stream down before reconnecting */
        a314_cmd(sync_ior, sync_mp, A314_RESET, NULL, 0);
        connected = FALSE;
    }
}

static void drain_job_port(void)
{
    struct Message *m;
    while ((m = GetMsg(agent_port)))
        handle_job_msg((struct JobMsg *)m);
}

static BOOL wait_ticks(ULONG ticks)
{
    for (ULONG i = 0; i < ticks; i += 5) {
        Delay(5);
        if (SetSignal(0, 0) & SIGBREAKF_CTRL_C)
            return FALSE;
        drain_job_port();
    }
    return TRUE;
}

static void cleanup(void)
{
    input_cleanup();
    screen_cleanup();
    if (sync_ior && sync_ior->a314_Request.io_Device)
        CloseDevice((struct IORequest *)sync_ior);
    if (read_ior)
        DeleteExtIO((struct IORequest *)read_ior);
    if (sync_ior)
        DeleteExtIO((struct IORequest *)sync_ior);
    if (async_mp)
        DeletePort(async_mp);
    if (sync_mp)
        DeletePort(sync_mp);
    if (agent_port)
        DeletePort(agent_port);
    struct Task *me = FindTask(NULL);
    if (me->tc_TrapCode == (APTR)tfdbg_trap) {
        me->tc_TrapCode = agent_job.old_trapcode;
        me->tc_TrapData = old_trapdata;
    }
    if (ExpansionBase)
        CloseLibrary((struct Library *)ExpansionBase);
}

int main(void)
{
    LONG args[2] = { 0, 0 };
    struct RDArgs *rda = ReadArgs("READONLY/S,NOREBOOT/S", args, NULL);
    if (!rda) {
        PrintFault(IoErr(), "tfdbgd");
        return RETURN_FAIL;
    }
    readonly = args[0] != 0;
    noreboot = args[1] != 0;
    FreeArgs(rda);

    if (!(SysBase->AttnFlags & AFF_68020)) {
        PutStr("tfdbgd: needs a 68020 or better\n");
        return RETURN_FAIL;
    }
    if (SysBase->LibNode.lib_Version < 39) {
        PutStr("tfdbgd: needs Kickstart 3.0 or newer\n");
        return RETURN_FAIL;
    }

    ExpansionBase = (struct ExpansionBase *)OpenLibrary("expansion.library", 37);
    NewList((struct List *)&jobs);

    /* our own trap handler protects memory probes */
    struct Task *me = FindTask(NULL);
    agent_job.magic = JOB_MAGIC;
    agent_job.is_agent = 1;
    agent_job.old_trapcode = me->tc_TrapCode ? me->tc_TrapCode : SysBase->TaskTrapCode;
    old_trapdata = me->tc_TrapData;
    me->tc_TrapData = &agent_job;
    me->tc_TrapCode = (APTR)tfdbg_trap;

    agent_port = CreatePort(NULL, 0);
    sync_mp = CreatePort(NULL, 0);
    async_mp = CreatePort(NULL, 0);
    sync_ior = agent_port && sync_mp ? (struct A314_IORequest *)CreateExtIO(sync_mp, sizeof(struct A314_IORequest)) : NULL;
    read_ior = async_mp ? (struct A314_IORequest *)CreateExtIO(async_mp, sizeof(struct A314_IORequest)) : NULL;
    if (!sync_ior || !read_ior) {
        PutStr("tfdbgd: out of memory\n");
        cleanup();
        return RETURN_FAIL;
    }

    while (OpenDevice(A314_NAME, 0, (struct IORequest *)sync_ior, 0)) {
        PutStr("tfdbgd: no " A314_NAME ", retrying\n");
        if (!wait_ticks(200)) {
            cleanup();
            return RETURN_OK;
        }
    }
    CopyMem(sync_ior, read_ior, sizeof(struct A314_IORequest));
    read_ior->a314_Request.io_Message.mn_ReplyPort = async_mp;

    ULONG readsig = 1UL << async_mp->mp_SigBit;
    ULONG jobsig = 1UL << agent_port->mp_SigBit;
    ULONG attempt = 0;

    while (!quit) {
        struct DateStamp ds;
        DateStamp(&ds);
        a314_socket = (ds.ds_Minute * 3000 + ds.ds_Tick) ^ (attempt++ << 20) ^ (ULONG)me;
        if (quit)
            break;
        if (a314_cmd(sync_ior, sync_mp, A314_CONNECT, SERVICE_NAME, strlen(SERVICE_NAME)) != A314_CONNECT_OK) {
            if (!wait_ticks(200)) {
                if (!jobs_running())
                    break;
                PutStr("tfdbgd: jobs are running, not quitting\n");
            }
            continue;
        }
        connected = TRUE;
        reset_frame();
        start_read();

        while (connected || pending_read) {
            ULONG sig = Wait(readsig | jobsig | SIGBREAKF_CTRL_C);
            if (sig & readsig) {
                if (GetMsg(async_mp))
                    handle_read_done();
            }
            if (sig & jobsig)
                drain_job_port();
            if (sig & SIGBREAKF_CTRL_C) {
                if (jobs_running()) {
                    PutStr("tfdbgd: jobs are running, not quitting\n");
                } else {
                    quit = TRUE;
                }
            }
            if (quit && connected) {
                connected = FALSE;
                a314_cmd(sync_ior, sync_mp, A314_RESET, NULL, 0);
            }
            if (!connected && pending_read) {
                AbortIO((struct IORequest *)read_ior);
                WaitIO((struct IORequest *)read_ior);
                pending_read = FALSE;
            }
        }
        reset_frame();
    }

    /* wait for workers still finishing (none are running when we get here) */
    drain_job_port();
    cleanup();
    return RETURN_OK;
}
