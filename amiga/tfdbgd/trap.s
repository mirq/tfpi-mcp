; tfdbgd low-level parts (vasm, Motorola syntax).
;
; tc_TrapCode of every job worker and of the agent itself is _tfdbg_trap.
; Exec calls it in supervisor mode with the vector number on the stack:
;
;     (sp)  ULONG vector number
;     4(sp) exception frame (SR, PC, format/vector, ...)
;
; The decisions are made in C (_tfdbg_trap_c, see jobs.c), which returns
;
;     0      not ours: chain to the original trap handler
;     n > 0  n = size of the frame; C has rewritten its first 8 bytes as a
;            format-0 frame (SR, PC, vector). The frame is shrunk to those 8
;            bytes and we RTE to the new PC.
;
; A stopped job runs _tfdbg_stub in user mode, in its own task: the stub saves
; the registers, reports to the agent (C) and waits, then restores them and
; resumes through "trap #15", which the C side turns back into the saved
; SR/PC (plus the trace bit when stepping), and USP from the saved A7.

	machine	68060

	xdef	_tfdbg_trap
	xdef	_tfdbg_stub
	xdef	_tfdbg_stub_after
	xdef	_tfdbg_except
	xdef	_tfdbg_probe_copy
	xdef	_tfdbg_probe_fault
	xdef	_tfdbg_flush_super
	xdef	_tfdbg_new_usp
	xdef	_tfdbg_chain

	xref	_tfdbg_trap_c
	xref	_tfdbg_stopped
	xref	_tfdbg_except_c

AttnFlags	equ	296
AFB_68020	equ	1
AFB_68040	equ	3
AFB_68060	equ	7

	section	code,code

_tfdbg_trap:
	movem.l	d0-d1/a0-a1,-(sp)	; 16 bytes; vector at 16(sp), frame at 20(sp)
	move.l	usp,a0
	move.l	a0,-(sp)		; arg 3: the task's user stack pointer
	pea	24(sp)			; arg 2: the frame
	move.l	24(sp),-(sp)		; arg 1: vector number
	jsr	_tfdbg_trap_c
	lea	12(sp),sp
	move.l	_tfdbg_new_usp,d1	; resume: user stack from the saved A7
	beq.s	.nousp
	move.l	d1,a1
	move.l	a1,usp
	clr.l	_tfdbg_new_usp
.nousp:
	tst.l	d0
	beq.s	.chain
	; move the 8-byte format-0 frame to the end of the old frame, then the
	; four saved registers just below it (copying downwards: dst >= src)
	lea	20(sp,d0.l),a1		; end of the old frame
	lea	20(sp),a0		; start of the old frame
	move.l	4(a0),-(a1)
	move.l	(a0),-(a1)
	move.l	12(sp),-(a1)
	move.l	8(sp),-(a1)
	move.l	4(sp),-(a1)
	move.l	(sp),-(a1)
	move.l	a1,sp
	movem.l	(sp)+,d0-d1/a0-a1
	rte
.chain:
	movem.l	(sp)+,d0-d1/a0-a1
	move.l	_tfdbg_chain,-(sp)	; jump with the vector still on the stack
	rts

; User mode, in the stopped task, on the job's own debugger stack (the trap
; handler switched USP; the program's A7 is in job->stop_usp). Registers
; are as at the exception; the trap handler kept PC/SR in the job.
_tfdbg_stub:
	movem.l	d0-d7/a0-a6,-(sp)	; regs[0..14]
	move.l	sp,-(sp)
	jsr	_tfdbg_stopped
	addq.l	#4,sp
	movem.l	(sp)+,d0-d7/a0-a6	; possibly changed by the debugger
	trap	#15			; resume (see _tfdbg_trap_c)
_tfdbg_stub_after:
	illegal				; never reached

; tc_ExceptCode of exec-mode workers: the agent signals the pause signal to
; stop a running job. Called by exec in user mode with D0 = signals. Always
; returns normally (no kill from here: the program may be inside the OS).
_tfdbg_except:
	movem.l	d0-d7/a0-a6,-(sp)
	move.l	sp,-(sp)
	jsr	_tfdbg_except_c
	addq.l	#4,sp
	movem.l	(sp)+,d0-d7/a0-a6	; D0 = the signals, as exec wants back
	rts

; LONG tfdbg_probe_copy(void *src, void *dst, ULONG len, ULONG width)
; 0 when done, -1 after a bus/address error (the trap handler resumes the
; agent at _tfdbg_probe_fault). Uses only scratch registers and no stack, so
; resuming at the fault label is safe.
_tfdbg_probe_copy:
	move.l	4(sp),a0
	move.l	8(sp),a1
	move.l	12(sp),d0
	move.l	16(sp),d1
	cmp.l	#4,d1
	beq.s	.long
	cmp.l	#2,d1
	beq.s	.word
.byte:
	subq.l	#1,d0
	bcs.s	.ok
	move.b	(a0)+,(a1)+
	bra.s	.byte
.word:
	subq.l	#2,d0
	bcs.s	.ok
	move.w	(a0)+,(a1)+
	bra.s	.word
.long:
	subq.l	#4,d0
	bcs.s	.ok
	move.l	(a0)+,(a1)+
	bra.s	.long
.ok:
	moveq	#0,d0
	rts
_tfdbg_probe_fault:
	moveq	#-1,d0
	rts

; Flush/invalidate the caches after patching code. Supervisor mode only.
_tfdbg_flush_super:
	move.l	4.w,a0
	move.w	AttnFlags(a0),d0
	btst	#AFB_68060,d0
	bne.s	.c040
	btst	#AFB_68040,d0
	bne.s	.c040
	btst	#AFB_68020,d0
	beq.s	.done
	movec	cacr,d0
	or.w	#$0808,d0		; clear instruction + data cache (020/030)
	movec	d0,cacr
	rts
.c040:
	nop
	cpusha	bc
	nop
.done:
	rts

	section	data,data

_tfdbg_new_usp:	dc.l	0
_tfdbg_chain:	dc.l	0
