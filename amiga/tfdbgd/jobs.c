/*
 * Jobs: programs started for the Pi, each in its own worker process.
 *
 * MODE_EXEC: the worker LoadSegs the program and runs it with RunCommand()
 * in its own context (it has a CLI, so CLI startup code works), through a
 * 12-byte trampoline that records the stack pointer at entry. The worker's
 * tc_TrapCode catches the program's exceptions (crashes, breakpoints,
 * single steps) and parks it in _tfdbg_stub until the Pi says how to go on.
 * Kill = return from the program into RunCommand with the saved entry SP.
 *
 * MODE_SHELL: SystemTags() runs the command line through the user shell;
 * no debugging, Ctrl-C goes to the CLIs that appeared after the start.
 */

#include <exec/types.h>
#include <exec/memory.h>
#include <exec/execbase.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <dos/dostags.h>

#include <proto/exec.h>
#include <proto/dos.h>

#include <string.h>
#include <stddef.h>

#include "tfdbgd.h"

struct MinList jobs;
static ULONG next_id = 1;

#define JOB_OF(n) ((struct Job *)((UBYTE *)(n) - offsetof(struct Job, node)))

static struct Job *find_job(ULONG id)
{
    for (struct MinNode *n = jobs.mlh_Head; n->mln_Succ; n = n->mln_Succ)
        if (JOB_OF(n)->id == id)
            return JOB_OF(n);
    return NULL;
}

ULONG jobs_running(void)
{
    ULONG count = 0;
    for (struct MinNode *n = jobs.mlh_Head; n->mln_Succ; n = n->mln_Succ)
        count++;
    return count;
}

static void free_job(struct Job *job)
{
    if (job->cmdline) FreeVec(job->cmdline);
    if (job->cwd) FreeVec(job->cwd);
    if (job->out_path) FreeVec(job->out_path);
    if (job->in_path) FreeVec(job->in_path);
    if (job->dbg_stack) FreeVec(job->dbg_stack);
    job->magic = 0;
    FreeVec(job);
}

/* ---- segments and breakpoints ---------------------------------------------- */

void put_segs(struct Buf *b, BPTR seglist)
{
    UWORD n = 0;
    for (BPTR s = seglist; s && n < 200; s = *(BPTR *)BADDR(s))
        n++;
    buf_u16(b, n);
    BPTR s = seglist;
    for (UWORD i = 0; i < n; i++, s = *(BPTR *)BADDR(s)) {
        ULONG *p = BADDR(s);
        buf_u32(b, (ULONG)(p + 1));
        buf_u32(b, p[-1] - 8);      /* allocation size includes the size and next longs */
    }
}

static BOOL in_segs(struct Job *job, ULONG addr, ULONG len)
{
    UWORD n = 0;
    for (BPTR s = job->seglist; s && n < 200; s = *(BPTR *)BADDR(s), n++) {
        ULONG *p = BADDR(s);
        ULONG lo = (ULONG)(p + 1), hi = lo + p[-1] - 8;
        if (addr >= lo && addr + len <= hi)
            return TRUE;
    }
    return FALSE;
}

/* also called from the trap handler (supervisor mode): no OS calls */
static LONG bp_index(struct Job *job, ULONG addr)
{
    for (ULONG i = 0; i < job->nbp; i++)
        if (job->bp_addr[i] == addr)
            return i;
    return -1;
}

/* Breakpoint edits happen with interrupts off and the caches flushed before
 * they come back, so the job never runs half-patched code. The worker
 * removes all of them (in Forbid) before unloading the program. */
static UBYTE bp_insert(struct Job *job, ULONG addr)
{
    if (job->resident || job->exiting || !job->seglist)
        return ST_UNSUPPORTED;
    if ((addr & 1) || !in_segs(job, addr, 2))
        return ST_BAD_ADDRESS;
    if (bp_index(job, addr) >= 0)
        return ST_OK;
    if (job->nbp >= MAX_BP)
        return ST_NO_MEMORY;
    Disable();
    job->bp_addr[job->nbp] = addr;
    job->bp_orig[job->nbp] = *(UWORD *)addr;
    job->nbp++;
    *(volatile UWORD *)addr = ILLEGAL_OP;
    CacheClearU();
    Enable();
    return ST_OK;
}

static void bp_remove_at(struct Job *job, LONG i)
{
    ULONG addr = job->bp_addr[i];
    Disable();
    if (*(UWORD *)addr == ILLEGAL_OP)
        *(volatile UWORD *)addr = job->bp_orig[i];
    if (job->reinsert_addr == addr)
        job->reinsert_addr = 0;
    for (ULONG k = i; k + 1 < job->nbp; k++) {
        job->bp_addr[k] = job->bp_addr[k + 1];
        job->bp_orig[k] = job->bp_orig[k + 1];
    }
    job->nbp--;
    CacheClearU();
    Enable();
}

static void bp_remove_all(struct Job *job)
{
    while (job->nbp)
        bp_remove_at(job, job->nbp - 1);
}

/* ---- the trap handler (supervisor mode, called from trap.s) ------------------ */

static ULONG frame_size(UWORD fmt)
{
    switch (fmt) {
    case 0: case 1: return 8;
    case 2: case 3: return 12;
    case 4: return 16;
    case 7: return 60;
    case 9: return 20;
    case 0xA: return 32;
    case 0xB: return 92;
    default: return 0;
    }
}

static void set_frame(UWORD *f, UWORD sr, ULONG pc, ULONG vec)
{
    f[0] = sr;
    f[1] = pc >> 16;
    f[2] = pc;
    f[3] = (vec << 2) & 0x0FFF;     /* format 0 */
}

ULONG tfdbg_trap_c(ULONG vec, UWORD *f, ULONG usp)
{
    struct ExecBase *sb = *(struct ExecBase **)4;
    struct Job *job = sb->ThisTask->tc_TrapData;
    tfdbg_chain = sb->TaskTrapCode;
    if (!job || job->magic != JOB_MAGIC)
        return 0;
    if (job->old_trapcode)
        tfdbg_chain = job->old_trapcode;
    UWORD sr = f[0];
    ULONG pc = ((ULONG)f[1] << 16) | f[2];
    UWORD fmt = f[3] >> 12;
    ULONG size = frame_size(fmt);
    if (!size || (sr & 0x2000))
        return 0;                   /* unknown frame, or raised in supervisor mode */

    if (job->is_agent) {
        if (job->probing && (vec == 2 || vec == 3)) {
            job->probing = 0;
            job->probe_faulted = 1;
            set_frame(f, sr & 0x071F, (ULONG)tfdbg_probe_fault, vec);
            return size;
        }
        return 0;
    }

    if (vec == 47 && pc == (ULONG)tfdbg_stub_after && job->resuming) {
        job->resuming = 0;
        set_frame(f, (job->sr & 0x071F) | (job->trace ? 0x8000 : 0), job->pc, vec);
        tfdbg_new_usp = job->regs[15];
        return size;
    }

    UBYTE reason;
    if (vec == 9) {
        if (job->reinsert_addr) {
            *(volatile UWORD *)job->reinsert_addr = ILLEGAL_OP;
            job->reinsert_addr = 0;
            tfdbg_flush_super();
        }
        if (!job->stepping) {
            job->trace = 0;
            set_frame(f, sr & 0x071F, pc, vec);
            return size;
        }
        reason = SR_STEP;
    } else if (vec == 4 && bp_index(job, pc) >= 0) {
        reason = SR_BREAKPOINT;
    } else {
        reason = SR_EXCEPTION;
    }
    if (job->in_debugger || !job->dbg_stack_top)
        return 0;                   /* fault inside the stub itself: leave it to exec */

    job->fault_addr = 0;
    job->fault_status = 0;
    switch (fmt) {
    case 2: case 3:
        job->fault_addr = *(ULONG *)(f + 4);
        break;
    case 4:                         /* 68060 access fault: EA, FSLW */
        job->fault_addr = *(ULONG *)(f + 4);
        job->fault_status = *(ULONG *)(f + 6);
        break;
    case 7:                         /* 68040 access error: EA, SSW */
        job->fault_addr = *(ULONG *)(f + 10);
        job->fault_status = f[6];
        break;
    case 0xA: case 0xB:             /* 68020/030 bus error: data fault address, SSW */
        job->fault_addr = *(ULONG *)(f + 8);
        job->fault_status = f[5];
        break;
    }
    job->pc = pc;
    job->sr = sr;
    job->vector = vec;
    job->format = fmt;
    job->stop_reason = reason;
    job->stepping = 0;
    job->trace = 0;
    /* 020/030/040 fault frames carry state needed to finish the instruction:
       after dropping them, resuming at pc is only allowed once pc is changed */
    job->lossy = reason == SR_EXCEPTION && (fmt == 7 || fmt == 0xA || fmt == 0xB);
    job->stop_usp = usp;
    job->in_debugger = 1;
    tfdbg_new_usp = job->dbg_stack_top;     /* don't trust the program's stack */
    set_frame(f, sr & 0x071F, (ULONG)tfdbg_stub, vec);
    return size;
}

/* ---- stopping (user mode, in the job's task) --------------------------------- */

/* the agent marks the job stopped when it takes the message (handle_job_msg) */
static void report_stop(struct Job *job)
{
    job->stop_msg.kind = JM_STOPPED;
    job->stop_msg.job = job;
    job->stop_msg.msg.mn_ReplyPort = job->wport;
    job->stop_msg.msg.mn_Length = sizeof(struct JobMsg);
    PutMsg(agent_port, &job->stop_msg.msg);
    for (;;) {
        WaitPort(job->wport);
        if (GetMsg(job->wport) == &job->stop_msg.msg)
            break;
    }
}

void tfdbg_stopped(ULONG *regs)
{
    struct Job *job = FindTask(NULL)->tc_TrapData;
    CopyMem(regs, job->regs, 15 * 4);
    job->regs[15] = job->stop_usp;
    job->regs_exact = 1;
    report_stop(job);

    if (job->resume_mode == RM_KILL) {
        ULONG sp = job->entry_sp;
        job->killed = 1;
        job->regs[0] = job->kill_rc;
        job->pc = *(ULONG *)sp;     /* return address into RunCommand */
        job->regs[15] = sp + 4;
        job->trace = job->stepping = 0;
    } else {
        job->trace = job->stepping = job->resume_mode == RM_STEP;
        LONG i = bp_index(job, job->pc);
        if (i >= 0 && *(UWORD *)job->pc == ILLEGAL_OP) {
            /* run the real instruction once, put the breakpoint back after it */
            *(volatile UWORD *)job->pc = job->bp_orig[i];
            CacheClearU();
            job->reinsert_addr = job->pc;
            job->trace = 1;
        }
    }
    CopyMem(job->regs, regs, 15 * 4);
    job->in_debugger = 0;
    job->resuming = 1;              /* the trap #15 in the stub resumes */
}

/* A pause: the program is stopped wherever it was (maybe inside the OS), so
 * only "continue" is allowed afterwards. */
void tfdbg_except_c(ULONG *regs)
{
    struct Job *job = FindTask(NULL)->tc_ExceptData;
    if (!job || job->magic != JOB_MAGIC || !(regs[0] & job->pause_sig))
        return;
    if (job->in_debugger || job->exiting)
        return;
    job->in_debugger = 1;
    CopyMem(regs, job->regs, 15 * 4);
    job->regs[15] = (ULONG)regs + 60;
    job->regs_exact = 0;            /* registers of the exception handler, not the program */
    job->pc = 0;
    job->sr = 0;
    job->vector = 0;
    job->format = 0;
    job->lossy = 0;
    job->fault_addr = job->fault_status = 0;
    job->stop_reason = SR_PAUSE;
    report_stop(job);
    job->in_debugger = 0;
}

/* ---- the worker process ------------------------------------------------------ */

static void notify(struct Job *job, struct JobMsg *m, UBYTE kind, BOOL wait)
{
    m->kind = kind;
    m->job = job;
    m->msg.mn_ReplyPort = job->wport;
    m->msg.mn_Length = sizeof(struct JobMsg);
    PutMsg(agent_port, &m->msg);
    if (wait)
        for (;;) {
            WaitPort(job->wport);
            if (GetMsg(job->wport) == &m->msg)
                break;
        }
}

static BPTR try_load(const char *path, BPTR *home)
{
    BPTR seg = LoadSeg((STRPTR)path);
    if (seg) {
        BPTR l = Lock((STRPTR)path, SHARED_LOCK);
        if (l) {
            *home = ParentDir(l);
            UnLock(l);
        }
    }
    return seg;
}

static BPTR load_program(const char *name, struct CommandLineInterface *cli, BPTR *home,
                         struct Segment **res, BOOL allow_resident)
{
    BPTR seg;
    BOOL has_path = strchr(name, ':') || strchr(name, '/');
    *home = 0;
    *res = NULL;
    if (!has_path && allow_resident) {
        Forbid();
        struct Segment *s = FindSegment((STRPTR)name, NULL, FALSE);
        if (!s)
            s = FindSegment((STRPTR)name, NULL, TRUE);
        if (s && s->seg_UC >= 0) {
            s->seg_UC++;
            *res = s;
            seg = s->seg_Seg;
            Permit();
            return seg;
        }
        Permit();
    }
    if ((seg = try_load(name, home)))
        return seg;
    if (has_path || !cli)
        return 0;
    for (BPTR p = cli->cli_CommandDir; p; p = ((BPTR *)BADDR(p))[0]) {
        BPTR old = CurrentDir(((BPTR *)BADDR(p))[1]);
        seg = try_load(name, home);
        CurrentDir(old);
        if (seg)
            return seg;
    }
    char cpath[264];
    strcpy(cpath, "C:");
    strncat(cpath, name, sizeof(cpath) - 3);
    return try_load(cpath, home);
}

/* first word of the command line (quotes allowed) into name; returns the rest */
static const char *split_command(const char *line, char *name, ULONG size)
{
    ULONG n = 0;
    while (*line == ' ' || *line == '\t')
        line++;
    if (*line == '"') {
        line++;
        while (*line && *line != '"') {
            if (n + 1 < size) name[n++] = *line;
            line++;
        }
        if (*line == '"')
            line++;
    } else {
        while (*line && *line != ' ' && *line != '\t' && *line != '\n') {
            if (n + 1 < size) name[n++] = *line;
            line++;
        }
    }
    name[n] = 0;
    while (*line == ' ' || *line == '\t')
        line++;
    return line;
}

static void run_exec(struct Job *job, struct Process *me, struct CommandLineInterface *cli)
{
    char name[256];
    const char *args = split_command(job->cmdline, name, sizeof(name));
    BPTR home;
    struct Segment *res;
    /* a debugged program gets its own copy: breakpoints in a shared
       resident segment would hit every other user of it */
    BPTR seg = load_program(name, cli, &home, &res, !(job->flags & RF_STOP_ENTRY));
    job->resident = res != NULL;
    BOOL module_set = FALSE;
    if (!seg) {
        job->rc = RETURN_FAIL;
        job->result2 = IoErr() ? IoErr() : ERROR_OBJECT_NOT_FOUND;
        job->exit_kind = EX_LOAD_FAILED;
        return;
    }

    ULONG arglen = strlen(args);
    STRPTR argline = AllocVec(arglen + 2, MEMF_ANY);
    ULONG *tramp = AllocVec(32, MEMF_PUBLIC | MEMF_CLEAR);
    ULONG sigbit = (ULONG)AllocSignal(-1);
    if (!argline || !tramp || sigbit == (ULONG)-1) {
        job->rc = RETURN_FAIL;
        job->result2 = ERROR_NO_FREE_STORE;
        job->exit_kind = EX_LOAD_FAILED;
        goto out;
    }
    CopyMem((APTR)args, argline, arglen);
    argline[arglen] = '\n';
    argline[arglen + 1] = 0;

    /* trampoline segment: move.l a7,(entry_sp).l ; jmp (entry).l */
    job->seglist = seg;
    job->entry = (ULONG)BADDR(seg) + 4;
    tramp[0] = 32;
    tramp[1] = 0;
    UWORD *c = (UWORD *)&tramp[2];
    ULONG spaddr = (ULONG)&job->entry_sp;
    c[0] = 0x23CF; c[1] = spaddr >> 16; c[2] = spaddr;
    c[3] = 0x4EF9; c[4] = job->entry >> 16; c[5] = job->entry;
    CacheClearU();
    job->tramp = tramp;

    /* the agent sends JOB_STARTED (and sets the entry breakpoint) before we go on */
    notify(job, &job->started_msg, JM_STARTED, TRUE);

    struct Task *t = &me->pr_Task;
    APTR old_trapcode = t->tc_TrapCode, old_trapdata = t->tc_TrapData;
    APTR old_exccode = t->tc_ExceptCode, old_excdata = t->tc_ExceptData;
    job->pause_sig = 1UL << sigbit;
    if (job->flags & (RF_CATCH | RF_STOP_ENTRY)) {
        t->tc_TrapData = job;
        t->tc_TrapCode = (APTR)tfdbg_trap;
    }
    job->old_trapcode = old_trapcode;
    t->tc_ExceptData = job;
    t->tc_ExceptCode = (APTR)tfdbg_except;
    SetExcept(job->pause_sig, job->pause_sig);

    BPTR old_home = me->pr_HomeDir;
    me->pr_HomeDir = home;
    if (cli && !res) {
        cli->cli_Module = seg;
        module_set = TRUE;
    }
    SetProgramName(name);
    SetIoErr(0);
    job->state = JS_RUNNING;

    job->rc = RunCommand(MKBADDR(&tramp[1]), job->stack, argline, arglen + 1);
    job->result2 = IoErr();
    Forbid();
    job->exiting = 1;               /* no more pause/kill/breakpoints from the agent */
    Permit();

    SetExcept(0, job->pause_sig);
    t->tc_ExceptCode = old_exccode;
    t->tc_ExceptData = old_excdata;
    t->tc_TrapCode = old_trapcode;
    t->tc_TrapData = old_trapdata;
    me->pr_HomeDir = old_home;
    if (job->killed) {
        job->exit_kind = EX_KILLED;
        job->rc = job->kill_rc;
    }
    job->pause_sig = 0;
    if (job->rc == -1 && !job->killed)
        job->exit_kind = EX_LOAD_FAILED;    /* RunCommand could not allocate the stack */

    Forbid();
    bp_remove_all(job);
    job->seglist = 0;
    Permit();

out:
    if (res) {
        Forbid();
        res->seg_UC--;
        Permit();
    } else if (!module_set || cli->cli_Module == seg) {
        if (module_set)
            cli->cli_Module = 0;
        UnLoadSeg(seg);
    }   /* else the program took its seglist (detached): leave it */
    if (home)
        UnLock(home);
    if (sigbit != (ULONG)-1)
        FreeSignal(sigbit);
    if (tramp)
        FreeVec(tramp);
    job->tramp = NULL;
    if (argline)
        FreeVec(argline);
}

static void run_shell(struct Job *job)
{
    notify(job, &job->started_msg, JM_STARTED, TRUE);
    job->state = JS_RUNNING;
    job->rc = SystemTags(job->cmdline,
                         SYS_Input, Input(),
                         SYS_Output, Output(),
                         SYS_UserShell, TRUE,
                         NP_StackSize, job->stack,
                         TAG_END);
    job->result2 = IoErr();
    Forbid();
    job->exiting = 1;
    Permit();
    if (job->rc == -1)
        job->exit_kind = EX_LOAD_FAILED;
}

static void worker_entry(void)
{
    struct Process *me = (struct Process *)FindTask(NULL);
    struct Job *job = me->pr_Task.tc_UserData;
    struct CommandLineInterface *cli = Cli();
    BPTR my_in = Input(), my_out = Output();    /* NP_Input/NP_Output from rq_run */

    job->wport = CreateMsgPort();
    if (cli)
        cli->cli_DefaultStack = job->stack / 4;
    if (!job->wport) {
        job->rc = RETURN_FAIL;
        job->result2 = ERROR_NO_FREE_STORE;
        job->exit_kind = EX_LOAD_FAILED;
    } else if (job->mode == MODE_SHELL) {
        run_shell(job);
    } else {
        run_exec(job, me, cli);
    }
    if (job->wport) {
        DeleteMsgPort(job->wport);
        job->wport = NULL;
    }
    Forbid();
    job->exiting = 1;
    Permit();
    /* close the output before reporting the exit, so the Pi finds it complete */
    SelectOutput(0);
    SelectInput(0);
    me->pr_Flags &= ~(PRF_CLOSEINPUT | PRF_CLOSEOUTPUT);
    if (my_out)
        Close(my_out);
    if (my_in)
        Close(my_in);
    /* the agent frees the job when it gets this; it can't run before we are gone */
    Forbid();
    job->exit_msg.kind = JM_EXITED;
    job->exit_msg.job = job;
    job->exit_msg.msg.mn_ReplyPort = NULL;
    job->exit_msg.msg.mn_Length = sizeof(struct JobMsg);
    PutMsg(agent_port, &job->exit_msg.msg);
}

/* ---- messages from workers (agent task) ------------------------------------- */

void put_regs(struct Buf *b, struct Job *job)
{
    buf_u8(b, job->stop_reason);
    buf_u8(b, job->vector);
    buf_u16(b, job->format);
    buf_u32(b, job->fault_addr);
    buf_u32(b, job->fault_status);
    buf_u8(b, job->regs_exact);
    buf_u8(b, 0);
    buf_u16(b, job->sr);
    buf_u32(b, job->pc);
    for (int i = 0; i < 16; i++)
        buf_u32(b, job->regs[i]);
}

void handle_job_msg(struct JobMsg *m)
{
    struct Job *job = m->job;
    struct Buf b;
    buf_init(&b);
    switch (m->kind) {
    case JM_STARTED:
        job->state = JS_RUNNING;
        if (job->mode == MODE_EXEC && (job->flags & RF_STOP_ENTRY))
            bp_insert(job, job->entry);
        buf_u32(&b, job->id);
        buf_u32(&b, (ULONG)job->proc);
        buf_u8(&b, job->mode);
        buf_u8(&b, job->flags);
        buf_u16(&b, 0);
        buf_u32(&b, job->entry);
        if (job->mode == MODE_EXEC)
            put_segs(&b, job->seglist);
        else
            buf_u16(&b, 0);
        send_event(EV_JOB_STARTED, &b);
        ReplyMsg(&m->msg);
        break;
    case JM_STOPPED:
        job->state = JS_STOPPED;    /* only now may RQ_CONT reply to the message */
        buf_u32(&b, job->id);
        put_regs(&b, job);
        send_event(EV_JOB_STOP, &b);
        break;                      /* replied by RQ_CONT */
    case JM_EXITED:
        buf_u32(&b, job->id);
        buf_u32(&b, job->rc);
        buf_u32(&b, job->result2);
        buf_u8(&b, job->exit_kind);
        send_event(EV_JOB_EXIT, &b);
        Remove((struct Node *)&job->node);
        free_job(job);
        break;
    }
    buf_free(&b);
}

/* ---- requests ----------------------------------------------------------------- */

/* u8 mode, u8 flags, i8 pri, u8 pad, u32 stack, str cmdline, str cwd, str out, str in -> u32 id */
UBYTE rq_run(struct Rd *r, struct Buf *out)
{
    UBYTE mode = rd_u8(r), flags = rd_u8(r);
    BYTE pri = rd_u8(r);
    rd_u8(r);
    ULONG stack = rd_u32(r);
    if (r->bad || mode > MODE_SHELL)
        return ST_BAD_REQUEST;
    struct Job *job = AllocVec(sizeof(struct Job), MEMF_PUBLIC | MEMF_CLEAR);
    if (!job)
        return ST_NO_MEMORY;
    job->magic = JOB_MAGIC;
    job->mode = mode;
    job->flags = flags;
    job->pri = pri;
    job->stack = stack < 4096 ? (stack ? 4096 : 16384) : stack > 0x100000 ? 0x100000 : stack;
    job->cmdline = rd_str(r);
    job->cwd = rd_str(r);
    job->out_path = rd_str(r);
    job->in_path = rd_str(r);
    if (r->bad || !job->cmdline || !job->cwd || !job->out_path || !job->in_path || !job->cmdline[0]) {
        free_job(job);
        return ST_BAD_REQUEST;
    }
    if (mode == MODE_EXEC) {
        job->dbg_stack = AllocVec(8192, MEMF_PUBLIC);
        if (!job->dbg_stack) {
            free_job(job);
            return ST_NO_MEMORY;
        }
        job->dbg_stack_top = ((ULONG)job->dbg_stack + 8192 - 16) & ~3UL;
    }

    BPTR in = Open(job->in_path[0] ? job->in_path : (STRPTR)"NIL:", MODE_OLDFILE);
    BPTR outfh = in ? Open(job->out_path[0] ? job->out_path : (STRPTR)"NIL:", MODE_NEWFILE) : 0;
    BPTR dir = 0;
    if (outfh)
        dir = job->cwd[0] ? Lock(job->cwd, SHARED_LOCK)
                          : DupLock(((struct Process *)FindTask(NULL))->pr_CurrentDir);
    if (!in || !outfh || !dir) {
        LONG err = IoErr();
        if (dir) UnLock(dir);
        if (outfh) Close(outfh);
        if (in) Close(in);
        free_job(job);
        buf_u32(out, err);
        return ST_DOS_ERROR;
    }

    char pname[32];
    ULONG id = next_id++;
    strcpy(pname, "tfdbg job ");
    char num[12];
    int k = 0;
    ULONG v = id;
    do { num[k++] = '0' + v % 10; v /= 10; } while (v);
    int pl = strlen(pname);
    while (k) pname[pl++] = num[--k];
    pname[pl] = 0;

    Forbid();
    if (mode == MODE_SHELL) {
        LONG max = MaxCli();
        for (LONG n = 1; n <= max && n < 512; n++)
            if (FindCliProc(n))
                job->cli_seen[n >> 3] |= 1 << (n & 7);
    }
    struct Process *proc = CreateNewProcTags(NP_Entry, (ULONG)worker_entry,
                                             NP_Name, (ULONG)pname,
                                             NP_StackSize, 16384,
                                             NP_Priority, pri,
                                             NP_Cli, TRUE,
                                             NP_Input, in,
                                             NP_Output, outfh,
                                             NP_CloseInput, TRUE,
                                             NP_CloseOutput, TRUE,
                                             NP_CurrentDir, dir,
                                             TAG_END);
    if (!proc) {
        Permit();
        LONG err = IoErr();
        UnLock(dir);
        Close(outfh);
        Close(in);
        free_job(job);
        buf_u32(out, err ? err : ERROR_NO_FREE_STORE);
        return ST_DOS_ERROR;
    }
    job->id = id;
    job->proc = proc;
    job->state = JS_STARTING;
    proc->pr_Task.tc_UserData = job;
    AddTail((struct List *)&jobs, (struct Node *)&job->node);
    Permit();
    buf_u32(out, id);
    return ST_OK;
}

/* -> u16 n, n x (u32 id, u8 mode, u8 state, u8 flags, u8 pad, u32 task, str cmdline) */
UBYTE rq_jobs(struct Rd *r, struct Buf *out)
{
    (void)r;
    buf_u16(out, jobs_running());
    for (struct MinNode *n = jobs.mlh_Head; n->mln_Succ; n = n->mln_Succ) {
        struct Job *job = JOB_OF(n);
        buf_u32(out, job->id);
        buf_u8(out, job->mode);
        buf_u8(out, job->state);
        buf_u8(out, job->flags);
        buf_u8(out, 0);
        buf_u32(out, (ULONG)job->proc);
        buf_str(out, job->cmdline);
    }
    return ST_OK;
}

/* u32 id, u8 op (0 clear, 1 set, 2 list, 3 clear all), u32 addr -> list: u16 n, n x u32 */
UBYTE rq_bp(struct Rd *r, struct Buf *out)
{
    ULONG id = rd_u32(r);
    UBYTE op = rd_u8(r);
    ULONG addr = rd_u32(r);
    if (r->bad)
        return ST_BAD_REQUEST;
    struct Job *job = find_job(id);
    if (!job)
        return ST_NO_JOB;
    if (job->mode != MODE_EXEC || !job->seglist || job->exiting || job->resident ||
        !(job->flags & (RF_CATCH | RF_STOP_ENTRY)))
        return ST_UNSUPPORTED;
    if (op != 2 && readonly)
        return ST_DENIED;
    UBYTE st = ST_OK;
    if (op == 1) {
        st = bp_insert(job, addr);
    } else if (op == 0) {
        LONG i = bp_index(job, addr);
        if (i < 0)
            return ST_BAD_ADDRESS;
        bp_remove_at(job, i);
    } else if (op == 3) {
        bp_remove_all(job);
    } else if (op != 2) {
        return ST_BAD_REQUEST;
    }
    if (st == ST_OK) {
        buf_u16(out, job->nbp);
        for (ULONG i = 0; i < job->nbp; i++)
            buf_u32(out, job->bp_addr[i]);
    }
    return st;
}

/* u32 id, u8 mode (RM_*), u32 kill rc */
UBYTE rq_cont(struct Rd *r, struct Buf *out)
{
    (void)out;
    ULONG id = rd_u32(r);
    UBYTE mode = rd_u8(r);
    LONG rc = rd_u32(r);
    if (r->bad || mode > RM_PAUSE)
        return ST_BAD_REQUEST;
    struct Job *job = find_job(id);
    if (!job || job->exiting)
        return ST_NO_JOB;
    if (job->state == JS_RUNNING) {
        if (mode != RM_PAUSE)
            return ST_NOT_STOPPED;  /* kill a running job with Ctrl-C (RQ_JOB_BREAK) */
        Forbid();
        BOOL ok = job->mode == MODE_EXEC && job->pause_sig && !job->exiting && !job->in_debugger;
        if (ok)
            Signal(&job->proc->pr_Task, job->pause_sig);
        Permit();
        return ok ? ST_OK : ST_UNSUPPORTED;
    }
    if (job->state != JS_STOPPED || mode == RM_PAUSE)
        return ST_NOT_STOPPED;
    if (mode == RM_KILL && readonly)
        return ST_DENIED;
    /* kill and step need the exact state of a breakpoint/step/crash stop */
    if ((mode == RM_KILL || mode == RM_STEP) && (!job->regs_exact || !job->entry_sp))
        return ST_UNSUPPORTED;
    if ((mode == RM_CONTINUE || mode == RM_STEP) && job->lossy)
        return ST_UNSUPPORTED;      /* change pc first (debug_registers) or kill */
    job->resume_mode = mode;
    job->kill_rc = rc;
    job->state = JS_RUNNING;
    ReplyMsg(&job->stop_msg.msg);
    return ST_OK;
}

/* u32 id -> regs (see put_regs) */
UBYTE rq_regs(struct Rd *r, struct Buf *out)
{
    struct Job *job = find_job(rd_u32(r));
    if (r->bad)
        return ST_BAD_REQUEST;
    if (!job)
        return ST_NO_JOB;
    if (job->state != JS_STOPPED)
        return ST_NOT_STOPPED;
    put_regs(out, job);
    return ST_OK;
}

/* u32 id, u8 index (0-7 d, 8-15 a, 16 pc, 17 sr), u32 value */
UBYTE rq_setreg(struct Rd *r, struct Buf *out)
{
    (void)out;
    struct Job *job = find_job(rd_u32(r));
    UBYTE idx = rd_u8(r);
    ULONG val = rd_u32(r);
    if (r->bad || idx > 17)
        return ST_BAD_REQUEST;
    if (!job)
        return ST_NO_JOB;
    if (readonly)
        return ST_DENIED;
    if (job->state != JS_STOPPED)
        return ST_NOT_STOPPED;
    if (!job->regs_exact)
        return ST_UNSUPPORTED;
    if (idx < 16)
        job->regs[idx] = val;
    else if (idx == 16) {
        if (val & 1)
            return ST_BAD_ADDRESS;
        job->pc = val;
        job->lossy = 0;
    } else
        job->sr = (job->sr & 0xFF00) | (val & 0x1F);     /* condition codes only */
    return ST_OK;
}

/* u32 id -> u32 entry, segs */
UBYTE rq_segs(struct Rd *r, struct Buf *out)
{
    struct Job *job = find_job(rd_u32(r));
    if (r->bad)
        return ST_BAD_REQUEST;
    if (!job)
        return ST_NO_JOB;
    buf_u32(out, job->entry);
    if (job->seglist)
        put_segs(out, job->seglist);
    else
        buf_u16(out, 0);
    return ST_OK;
}

/* u32 id, u32 signal mask (0: Ctrl-C) -> u16 number of processes signalled */
UBYTE rq_job_break(struct Rd *r, struct Buf *out)
{
    ULONG id = rd_u32(r);
    ULONG mask = rd_u32(r);
    if (r->bad)
        return ST_BAD_REQUEST;
    if (!mask)
        mask = SIGBREAKF_CTRL_C;
    mask &= SIGBREAKF_CTRL_C | SIGBREAKF_CTRL_D | SIGBREAKF_CTRL_E | SIGBREAKF_CTRL_F;
    struct Job *job = find_job(id);
    if (!job)
        return ST_NO_JOB;
    UWORD count = 0;
    Forbid();
    if (job->exiting) {
        /* finishing: nothing left to signal */
    } else if (job->mode == MODE_EXEC) {
        Signal(&job->proc->pr_Task, mask);
        count = 1;
    } else {
        LONG max = MaxCli();
        for (LONG n = 1; n <= max && n < 512; n++) {
            if (job->cli_seen[n >> 3] & (1 << (n & 7)))
                continue;
            struct Process *p = FindCliProc(n);
            if (!p || p == job->proc || &p->pr_Task == FindTask(NULL))
                continue;
            BOOL other = FALSE;
            for (struct MinNode *m = jobs.mlh_Head; m->mln_Succ; m = m->mln_Succ)
                if (JOB_OF(m)->proc == p)
                    other = TRUE;
            if (!other) {
                Signal(&p->pr_Task, mask);
                count++;
            }
        }
    }
    Permit();
    buf_u16(out, count);
    return ST_OK;
}
