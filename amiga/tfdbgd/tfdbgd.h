/*
 * tfdbgd - the Amiga side of tfpi-mcp: inspection, program control and a
 * small debugger, reached from the Pi over the a314 service "tfdbg".
 *
 * Wire protocol (both directions, big-endian), carried in the a314 stream:
 *
 *   u32 length   bytes after this field (8 + payload)
 *   u8  type     request type; replies use the same type; events are 0x40+
 *   u8  status   0 in requests; ST_* in replies
 *   u16 reserved
 *   u32 id       request id (echoed in the reply); 0 for events
 *   ...payload
 *
 * Payload layouts are documented next to each handler and mirrored in
 * tfmcp/proto.py on the Pi; keep the two in step (PROTO_VERSION).
 */
#ifndef TFDBGD_H
#define TFDBGD_H

#include <exec/types.h>
#include <exec/nodes.h>
#include <exec/lists.h>
#include <exec/ports.h>
#include <exec/tasks.h>
#include <dos/dos.h>
#include <dos/dosextens.h>

#define PROTO_VERSION   1
#define AGENT_VERSION   1
#define SERVICE_NAME    "tfdbg"

#define HDR_LEN         12          /* length field + type/status/rsv/id */
#define MAX_REQUEST     (64 * 1024 + 64)
#define MAX_CHUNK       (32 * 1024) /* largest mem/grab/file chunk per reply */

/* requests */
#define RQ_HELLO        1
#define RQ_MEM_READ     2
#define RQ_MEM_WRITE    3
#define RQ_TASKS        4
#define RQ_LIBS         5
#define RQ_MEMSTATS     6
#define RQ_SIGNAL       7
#define RQ_RUN          8
#define RQ_JOBS         9
#define RQ_BP           10
#define RQ_CONT         11
#define RQ_REGS         12
#define RQ_SETREG       13
#define RQ_SCREENS      14
#define RQ_GRAB         15
#define RQ_INPUT        16
#define RQ_REBOOT       17
#define RQ_SEGS         18
#define RQ_JOB_BREAK    19
#define RQ_QUIT         20
#define RQ_FILE_READ    21

/* events (id 0) */
#define EV_JOB_STARTED  0x41
#define EV_JOB_EXIT     0x42
#define EV_JOB_STOP     0x43
#define EV_LOG          0x44

/* reply status */
#define ST_OK           0
#define ST_BAD_REQUEST  1
#define ST_BAD_ADDRESS  2
#define ST_BUS_ERROR    3
#define ST_NO_JOB       4
#define ST_NOT_STOPPED  5
#define ST_DENIED       6
#define ST_NO_MEMORY    7
#define ST_DOS_ERROR    8       /* payload: u32 IoErr */
#define ST_UNSUPPORTED  9
#define ST_BUSY         10

/* run modes / flags */
#define MODE_EXEC       0       /* LoadSeg + RunCommand in our worker: debuggable */
#define MODE_SHELL      1       /* SystemTags(): redirection, scripts, internal commands */
#define RF_CATCH        1       /* catch crashes instead of a guru (exec mode) */
#define RF_STOP_ENTRY   2       /* stop on the first instruction */

/* job states */
#define JS_STARTING     0
#define JS_RUNNING      1
#define JS_STOPPED      2
#define JS_EXITED       3

/* stop reasons */
#define SR_BREAKPOINT   1
#define SR_STEP         2
#define SR_EXCEPTION    3
#define SR_PAUSE        4

/* resume modes (RQ_CONT) */
#define RM_CONTINUE     0
#define RM_STEP         1
#define RM_KILL         2       /* only from an exact stop (breakpoint, step, crash) */
#define RM_PAUSE        3       /* stop a running job (inexact: no kill/step from there) */

/* exit kinds */
#define EX_NORMAL       0
#define EX_KILLED       1
#define EX_LOAD_FAILED  2

#define MAX_BP          32
#define ILLEGAL_OP      0x4AFC
#define JOB_MAGIC       0x54464A42UL    /* 'TFJB' */

/* worker -> agent messages */
#define JM_STARTED      1
#define JM_STOPPED      2
#define JM_EXITED       3

struct Job;

struct JobMsg {
    struct Message msg;
    UBYTE kind;
    struct Job *job;
};

struct Job {
    ULONG magic;                /* first: the trap handler checks it */
    struct MinNode node;
    ULONG id;
    UBYTE mode, flags, state, is_agent;
    BYTE pri;
    ULONG stack;
    STRPTR cmdline;             /* AllocVec'd copies */
    STRPTR cwd;
    STRPTR out_path;
    STRPTR in_path;

    struct Process *proc;
    struct MsgPort *wport;      /* worker's reply port (created by the worker) */
    struct JobMsg started_msg, stop_msg, exit_msg;

    BPTR seglist;               /* the program's */
    ULONG *tramp;               /* trampoline segment (AllocVec) */
    ULONG entry;                /* first instruction of the program */
    volatile ULONG entry_sp;    /* SP at entry: (entry_sp) = return into RunCommand */
    LONG rc, result2;
    UBYTE exit_kind;
    UBYTE cli_seen[64];         /* shell mode: CLI numbers in use before start (bitmap) */

    /* debugger state (read/written by the trap handler in supervisor mode) */
    ULONG regs[16];             /* d0-d7, a0-a7 */
    ULONG pc;
    UWORD sr;
    UWORD format;
    UBYTE vector;
    UBYTE stop_reason;
    volatile UBYTE resuming;
    UBYTE trace;
    UBYTE stepping;
    UBYTE resume_mode;
    UBYTE killed;
    UBYTE regs_exact;           /* 0 for SR_PAUSE: taken in the task exception */
    ULONG fault_addr;
    ULONG fault_status;
    ULONG reinsert_addr;
    LONG kill_rc;
    ULONG nbp;
    ULONG bp_addr[MAX_BP];
    UWORD bp_orig[MAX_BP];
    ULONG pause_sig;
    APTR old_trapcode;          /* chained to for exceptions that aren't ours */
    UBYTE *dbg_stack;           /* the stub runs here, not on the program's stack */
    ULONG dbg_stack_top;
    ULONG stop_usp;             /* program's A7 at the stop */
    volatile UBYTE in_debugger; /* in _tfdbg_stub: pause requests are ignored */
    volatile UBYTE exiting;     /* RunCommand/SystemTags returned: no more control */
    UBYTE lossy;                /* 020/030/040 fault frame dropped: can't resume at pc */
    UBYTE resident;             /* running a shared resident segment: no breakpoints */

    /* the agent's own probe (is_agent) */
    volatile UBYTE probing;
    volatile UBYTE probe_faulted;
};

/* response builder */
struct Buf {
    UBYTE *data;
    ULONG len, cap;
    BOOL failed;
};

void buf_init(struct Buf *b);
void buf_free(struct Buf *b);
void buf_bytes(struct Buf *b, const void *p, ULONG n);
void buf_u8(struct Buf *b, UBYTE v);
void buf_u16(struct Buf *b, UWORD v);
void buf_u32(struct Buf *b, ULONG v);
void buf_str(struct Buf *b, const char *s);
void buf_bstr(struct Buf *b, BSTR s);
UBYTE *buf_reserve(struct Buf *b, ULONG n);

/* request reader */
struct Rd {
    const UBYTE *p;
    ULONG left;
    BOOL bad;
};
UBYTE rd_u8(struct Rd *r);
UWORD rd_u16(struct Rd *r);
ULONG rd_u32(struct Rd *r);
STRPTR rd_str(struct Rd *r);     /* AllocVec'd, NUL-terminated; NULL on error */

/* main.c */
extern struct MsgPort *agent_port;  /* worker -> agent */
extern struct Job agent_job;        /* the agent's own trap data (probes) */
extern BOOL readonly;
extern BOOL noreboot;
void send_event(UBYTE type, struct Buf *b);
LONG addr_check(ULONG addr, ULONG len, BOOL write, BOOL force);

/* jobs.c */
extern struct MinList jobs;
UBYTE rq_run(struct Rd *r, struct Buf *out);
UBYTE rq_jobs(struct Rd *r, struct Buf *out);
UBYTE rq_bp(struct Rd *r, struct Buf *out);
UBYTE rq_cont(struct Rd *r, struct Buf *out);
UBYTE rq_regs(struct Rd *r, struct Buf *out);
UBYTE rq_setreg(struct Rd *r, struct Buf *out);
UBYTE rq_segs(struct Rd *r, struct Buf *out);
UBYTE rq_job_break(struct Rd *r, struct Buf *out);
void handle_job_msg(struct JobMsg *m);
ULONG jobs_running(void);
void put_regs(struct Buf *b, struct Job *job);
void put_segs(struct Buf *b, BPTR seglist);

/* inspect.c */
UBYTE rq_mem_read(struct Rd *r, struct Buf *out);
UBYTE rq_mem_write(struct Rd *r, struct Buf *out);
UBYTE rq_tasks(struct Rd *r, struct Buf *out);
UBYTE rq_libs(struct Rd *r, struct Buf *out);
UBYTE rq_memstats(struct Rd *r, struct Buf *out);
UBYTE rq_signal(struct Rd *r, struct Buf *out);
UBYTE rq_file_read(struct Rd *r, struct Buf *out);
BOOL signal_task(struct Task *t, ULONG mask);
LONG probe_copy(void *src, void *dst, ULONG len, ULONG width);

/* screen.c */
UBYTE rq_screens(struct Rd *r, struct Buf *out);
UBYTE rq_grab(struct Rd *r, struct Buf *out);
void screen_cleanup(void);

/* input.c */
UBYTE rq_input(struct Rd *r, struct Buf *out);
void input_cleanup(void);

/* trap.s */
extern void tfdbg_trap(void);
extern void tfdbg_stub(void);
extern void tfdbg_stub_after(void);
extern void tfdbg_except(void);
extern void tfdbg_probe_fault(void);
extern void tfdbg_flush_super(void);
extern LONG tfdbg_probe_copy(void *src, void *dst, ULONG len, ULONG width);
extern volatile ULONG tfdbg_new_usp;
extern APTR tfdbg_chain;            /* where _tfdbg_trap chains to when C returns 0 */

#endif
