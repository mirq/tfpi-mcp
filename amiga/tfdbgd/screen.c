/* Screens: the list, and pixels for screenshots (planar rows, RGB from
 * cybergraphics.library for RTG screens, or the raw pen bytes of 8-bit RTG
 * screens). The Pi turns them into PNGs. */

#include <exec/types.h>
#include <exec/memory.h>
#include <graphics/gfx.h>
#include <graphics/view.h>
#include <graphics/modeid.h>
#include <intuition/intuition.h>
#include <intuition/intuitionbase.h>
#include <intuition/screens.h>
#include <utility/tagitem.h>

#include <proto/exec.h>
#include <proto/graphics.h>
#include <proto/intuition.h>

#include <inline/macros.h>

#include "tfdbgd.h"

struct Library *CyberGfxBase;
static BOOL cgx_tried;

#define CYBRMATTR_PIXFMT        0x80000004
#define CYBRMATTR_BPPIX         0x80000002
#define CYBRMATTR_ISCYBERGFX    0x80000008
#define RECTFMT_RGB             0
#define PIXFMT_LUT8             0
#define LBMI_BYTESPERROW        0x84001006
#define LBMI_BASEADDRESS        0x84001007

#define GetCyberMapAttr(bm, attr) \
    LP2(96, ULONG, GetCyberMapAttr, struct BitMap *, bm, a0, ULONG, attr, d0, , CyberGfxBase)
#define ReadPixelArray(dst, dx, dy, dmod, rp, sx, sy, w, h, fmt) \
    LP10(120, ULONG, ReadPixelArray, APTR, dst, a0, UWORD, dx, d0, UWORD, dy, d1, UWORD, dmod, d2, \
         struct RastPort *, rp, a1, UWORD, sx, d3, UWORD, sy, d4, UWORD, w, d5, UWORD, h, d6, \
         UBYTE, fmt, d7, , CyberGfxBase)

#define LockBitMapTagList(bm, tags) \
    LP2(168, APTR, LockBitMapTagList, APTR, bm, a0, struct TagItem *, tags, a1, , CyberGfxBase)
#define UnLockBitMap(handle) \
    LP1NR(174, UnLockBitMap, APTR, handle, a0, , CyberGfxBase)

static void open_cgx(void)
{
    if (!cgx_tried) {
        cgx_tried = TRUE;
        CyberGfxBase = OpenLibrary("cybergraphics.library", 40);
    }
}

void screen_cleanup(void)
{
    if (CyberGfxBase)
        CloseLibrary(CyberGfxBase);
    CyberGfxBase = NULL;
    cgx_tried = FALSE;
}

static BOOL is_rtg(struct BitMap *bm)
{
    return CyberGfxBase && GetCyberMapAttr(bm, CYBRMATTR_ISCYBERGFX);
}

/* call with LockIBase held */
static BOOL screen_exists(struct Screen *want)
{
    for (struct Screen *s = IntuitionBase->FirstScreen; s; s = s->NextScreen)
        if (s == want)
            return TRUE;
    return FALSE;
}

/* -> u16 n, n x (u32 screen, u32 bitmap, u16 width, u16 height, i16 left, i16 top,
 *    u16 depth, u16 flags (1 rtg, 2 frontmost), u32 modeid, u16 bytesperrow, u16 rows,
 *    u16 bmwidth, u16 bits per pixel (rtg), u32 pixfmt (rtg), 8 x u32 planes,
 *    u16 ncolors, ncolors x (r, g, b), str title) */
UBYTE rq_screens(struct Rd *r, struct Buf *out)
{
    (void)r;
    open_cgx();
    struct Screen *list[16];
    UWORD n = 0;
    ULONG *rgb = AllocVec(256 * 3 * 4, MEMF_ANY);
    if (!rgb)
        return ST_NO_MEMORY;
    /* the screens can't close while we hold the lock */
    ULONG lock = LockIBase(0);
    for (struct Screen *s = IntuitionBase->FirstScreen; s && n < 16; s = s->NextScreen)
        list[n++] = s;
    buf_u16(out, n);
    for (UWORD i = 0; i < n; i++) {
        struct Screen *s = list[i];
        struct BitMap *bm = s->RastPort.BitMap;
        BOOL rtg = is_rtg(bm);
        ULONG depth = GetBitMapAttr(bm, BMA_DEPTH);
        buf_u32(out, (ULONG)s);
        buf_u32(out, (ULONG)bm);
        buf_u16(out, s->Width);
        buf_u16(out, s->Height);
        buf_u16(out, s->LeftEdge);
        buf_u16(out, s->TopEdge);
        buf_u16(out, depth);
        buf_u16(out, (rtg ? 1 : 0) | (i == 0 ? 2 : 0));
        buf_u32(out, GetVPModeID(&s->ViewPort));
        buf_u16(out, bm->BytesPerRow);
        buf_u16(out, bm->Rows);
        buf_u16(out, GetBitMapAttr(bm, BMA_WIDTH));
        buf_u16(out, rtg ? GetCyberMapAttr(bm, CYBRMATTR_BPPIX) * 8 : 0);
        buf_u32(out, rtg ? GetCyberMapAttr(bm, CYBRMATTR_PIXFMT) : 0);
        for (int p = 0; p < 8; p++)
            buf_u32(out, !rtg && p < bm->Depth ? (ULONG)bm->Planes[p] : 0);
        UWORD ncol = depth <= 8 && s->ViewPort.ColorMap ? (1 << depth) : 0;
        if (ncol && ncol > s->ViewPort.ColorMap->Count)
            ncol = s->ViewPort.ColorMap->Count;
        buf_u16(out, ncol);
        if (ncol) {
            GetRGB32(s->ViewPort.ColorMap, 0, ncol, rgb);
            for (UWORD c = 0; c < ncol * 3; c++)
                buf_u8(out, rgb[c] >> 24);
        }
        buf_str(out, s->Title ? (char *)s->Title : (char *)s->DefaultTitle);
    }
    UnlockIBase(lock);
    FreeVec(rgb);
    return ST_OK;
}

/* u32 screen, u16 x, u16 y, u16 w, u16 h, u8 format (0 planar, 1 RGB, 2 LUT8)
 * planar: x must be a multiple of 16; for each row, for each plane, (w + 15) / 16 * 2 bytes
 * RGB: w * h * 3 bytes
 * LUT8 (8-bit RTG screens): w * h pen numbers. Picasso96 converts such
 * screens to RGB with the wrong colours, so the Pi maps them with the palette. */
UBYTE rq_grab(struct Rd *r, struct Buf *out)
{
    struct Screen *s = (struct Screen *)rd_u32(r);
    ULONG x = rd_u16(r), y = rd_u16(r), w = rd_u16(r), h = rd_u16(r);
    UBYTE fmt = rd_u8(r);
    if (r->bad || !w || !h || w > 8192 || h > 8192 || fmt > 2)
        return ST_BAD_REQUEST;
    open_cgx();
    /* size before allocating; both factors are bounded, so no overflow */
    ULONG rowbytes = (w + 15) / 16 * 2;
    UBYTE *dst = NULL;
    UBYTE st = ST_OK;
    ULONG lock = LockIBase(0);      /* keeps the screen open while we read it */
    if (!screen_exists(s)) {
        st = ST_BAD_ADDRESS;
        goto done;
    }
    struct BitMap *bm = s->RastPort.BitMap;
    if (x + w > (ULONG)s->Width || y + h > (ULONG)s->Height) {
        st = ST_BAD_ADDRESS;
        goto done;
    }
    if (fmt == 2) {
        if (!is_rtg(bm) || GetCyberMapAttr(bm, CYBRMATTR_PIXFMT) != PIXFMT_LUT8
                || GetCyberMapAttr(bm, CYBRMATTR_BPPIX) != 1) {
            st = ST_UNSUPPORTED;
            goto done;
        }
        ULONG size = w * h;
        if (size > MAX_CHUNK || !(dst = buf_reserve(out, size))) {
            st = size > MAX_CHUNK ? ST_BAD_REQUEST : ST_NO_MEMORY;
            goto done;
        }
        ULONG base = 0, bpr = 0;
        struct TagItem tags[] = {{LBMI_BASEADDRESS, (ULONG)&base}, {LBMI_BYTESPERROW, (ULONG)&bpr},
                                 {TAG_DONE, 0}};
        APTR handle = LockBitMapTagList(bm, tags);
        if (!handle) {
            st = ST_UNSUPPORTED;
            goto done;
        }
        if (!base || bpr < x + w)
            st = ST_UNSUPPORTED;
        for (ULONG row = 0; row < h && st == ST_OK; row++, dst += w)
            CopyMem((APTR)(base + (y + row) * bpr + x), dst, w);
        UnLockBitMap(handle);
        goto done;
    }
    if (fmt == 1) {
        if (!is_rtg(bm)) {
            st = ST_UNSUPPORTED;
            goto done;
        }
        ULONG size = w * h * 3;
        if (size > MAX_CHUNK || !(dst = buf_reserve(out, size))) {
            st = size > MAX_CHUNK ? ST_BAD_REQUEST : ST_NO_MEMORY;
            goto done;
        }
        if (!ReadPixelArray(dst, 0, 0, w * 3, &s->RastPort, x, y, w, h, RECTFMT_RGB))
            st = ST_UNSUPPORTED;
        goto done;
    }
    if (is_rtg(bm) || (x & 15)) {
        st = ST_BAD_REQUEST;
        goto done;
    }
    ULONG depth = bm->Depth;
    ULONG plane_bytes = (GetBitMapAttr(bm, BMA_WIDTH) + 15) / 16 * 2;   /* one plane's row, even if interleaved */
    if (y + h > bm->Rows || x / 8 + rowbytes > plane_bytes) {
        st = ST_BAD_ADDRESS;
        goto done;
    }
    ULONG size = rowbytes * depth * h;
    if (size > MAX_CHUNK || !(dst = buf_reserve(out, size))) {
        st = size > MAX_CHUNK ? ST_BAD_REQUEST : ST_NO_MEMORY;
        goto done;
    }
    for (ULONG row = y; row < y + h && st == ST_OK; row++)
        for (ULONG p = 0; p < depth; p++) {
            UBYTE *src = bm->Planes[p] + row * bm->BytesPerRow + x / 8;
            if (probe_copy(src, dst, rowbytes, 1)) {
                st = ST_BUS_ERROR;
                break;
            }
            dst += rowbytes;
        }
done:
    UnlockIBase(lock);
    return st;
}
