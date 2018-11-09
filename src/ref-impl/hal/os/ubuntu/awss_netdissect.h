/*
 * Copyright (c) 1988-1997
 *    The Regents of the University of California.  All rights reserved.
 *
 * Copyright (c) 1998-2012  Michael Richardson <mcr@tcpdump.org>
 *      The TCPDUMP project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef netdissect_h
#define netdissect_h

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif
#include <sys/types.h>

/*
 * Data types corresponding to multi-byte integral values within data
 * structures.  These are defined as arrays of octets, so that they're
 * not aligned on their "natural" boundaries, and so that you *must*
 * use the EXTRACT_ macros to extract them (which you should be doing
 * *anyway*, so as not to assume a particular byte order or alignment
 * in your code).
 *
 * We even want EXTRACT_U_1 used for 8-bit integral values, so we
 * define nd_uint8_t and nd_int8_t as arrays as well.
 */
typedef unsigned char nd_uint8_t[1];
typedef unsigned char nd_uint16_t[2];
typedef unsigned char nd_uint24_t[3];
typedef unsigned char nd_uint32_t[4];
typedef unsigned char nd_uint40_t[5];
typedef unsigned char nd_uint48_t[6];
typedef unsigned char nd_uint56_t[7];
typedef unsigned char nd_uint64_t[8];

typedef signed char nd_int8_t[1];

/*
 * "unsigned char" so that sign extension isn't done on the
 * individual bytes while they're being assembled.
 */
typedef unsigned char nd_int32_t[4];
typedef unsigned char nd_int64_t[8];

/*
 * Use this for IPv4 addresses and netmasks.
 *
 * It's defined as an array of octets, so that it's not guaranteed to
 * be aligned on its "natural" boundary (in some packet formats, it
 * *isn't* so aligned).  We have separate EXTRACT_ calls for them;
 * sometimes you want the host-byte-order value, other times you want
 * the network-byte-order value.
 *
 * Don't use EXTRACT_BE_U_4() on them, use EXTRACT_IPV4_TO_HOST_ORDER()
 * if you want them in host byte order and EXTRACT_IPV4_TO_NETWORK_ORDER()
 * if you want them in network byte order (which you want with system APIs
 * that expect network-order IPv4 addresses, such as inet_ntop()).
 *
 * If, on your little-endian machine (e.g., an "IBM-compatible PC", no matter
 * what the OS, or an Intel Mac, no matter what the OS), you get the wrong
 * answer, and you've used EXTRACT_BE_U_4(), do *N*O*T* "fix" this by using
 * EXTRACT_LE_U_4(), fix it by using EXTRACT_IPV4_TO_NETWORK_ORDER(),
 * otherwise you're breaking the result on big-endian machines (e.g.,
 * most PowerPC/Power ISA machines, System/390 and z/Architecture, SPARC,
 * etc.).
 *
 * Yes, people do this; that's why Wireshark has tvb_get_ipv4(), to extract
 * an IPv4 address from a packet data buffer; it was introduced in reaction
 * to somebody who *had* done that.
 */
typedef unsigned char nd_ipv4[4];

/*
 * Use this for IPv6 addresses and netmasks.
 */
typedef unsigned char nd_ipv6[16];

/*
 * Use this for MAC addresses.
 */
#define MAC_ADDR_LEN    6        /* length of MAC addresses */
typedef unsigned char nd_mac_addr[MAC_ADDR_LEN];

/*
 * Use this for blobs of bytes; make them arrays of nd_byte.
 */
typedef unsigned char nd_byte;

/*
 * Round up x to a multiple of y; y must be a power of 2.
 */
#ifndef roundup2
#define roundup2(x, y)    (((x)+((y)-1))&(~((y)-1)))
#endif

/* nd_snprintf et al */

#include <stdarg.h>

#ifndef min
#define min(a,b) ((a)>(b)?(b):(a))
#endif
#ifndef max
#define max(a,b) ((b)>(a)?(b):(a))
#endif

/*
 * Maximum snapshot length.  This should be enough to capture the full
 * packet on most network interfaces.
 *
 *
 * Somewhat arbitrary, but chosen to be:
 *
 *    1) big enough for maximum-size Linux loopback packets (65549)
 *       and some USB packets captured with USBPcap:
 *
 *           http://desowin.org/usbpcap/
 *
 *       (> 131072, < 262144)
 *
 * and
 *
 *    2) small enough not to cause attempts to allocate huge amounts of
 *       memory; some applications might use the snapshot length in a
 *       savefile header to control the size of the buffer they allocate,
 *       so a size of, say, 2^31-1 might not work well.
 *
 * XXX - does it need to be bigger still?  Note that, for versions of
 * libpcap with pcap_create()/pcap_activate(), if no -s flag is specified
 * or -s 0 is specified, we won't set the snapshot length at all, and will
 * let libpcap choose a snapshot length; newer versions may choose a bigger
 * value than 262144 for D-Bus, for example.
 */
#define MAXIMUM_SNAPLEN    262144

/*
 * True if "l" bytes from "p" were captured.
 *
 * The "ndo->ndo_snapend - (l) <= ndo->ndo_snapend" checks to make sure
 * "l" isn't so large that "ndo->ndo_snapend - (l)" underflows.
 *
 * The check is for <= rather than < because "l" might be 0.
 *
 * We cast the pointers to uintptr_t to make sure that the compiler
 * doesn't optimize away any of these tests (which it is allowed to
 * do, as adding an integer to, or subtracting an integer from, a
 * pointer assumes that the pointer is a pointer to an element of an
 * array and that the result of the addition or subtraction yields a
 * pointer to another member of the array, so that, for example, if
 * you subtract a positive integer from a pointer, the result is
 * guaranteed to be less than the original pointer value). See
 *
 *    http://www.kb.cert.org/vuls/id/162289
 */

/*
 * Test in two parts to avoid these warnings:
 * comparison of unsigned expression >= 0 is always true [-Wtype-limits],
 * comparison is always true due to limited range of data type [-Wtype-limits].
 */
#define IS_NOT_NEGATIVE(x) (((x) > 0) || ((x) == 0))

/*
 * Locale-independent macros for testing character properties and
 * stripping the 8th bit from characters.  Assumed to be handed
 * a value between 0 and 255, i.e. don't hand them a char, as
 * those might be in the range -128 to 127.
 */
#define ND_ISASCII(c)    (!((c) & 0x80))    /* value is an ASCII code point */
#define ND_ISPRINT(c)    ((c) >= 0x20 && (c) <= 0x7E)
#define ND_ISGRAPH(c)    ((c) > 0x20 && (c) <= 0x7E)
#define ND_TOASCII(c)    ((c) & 0x7F)

#if (defined(__i386__) || defined(_M_IX86) || defined(__X86__) || defined(__x86_64__) || defined(_M_X64)) || \
    (defined(__arm__) || defined(_M_ARM) || defined(__aarch64__)) || \
    (defined(__m68k__) && (!defined(__mc68000__) && !defined(__mc68010__))) || \
    (defined(__ppc__) || defined(__ppc64__) || defined(_M_PPC) || defined(_ARCH_PPC) || defined(_ARCH_PPC64)) || \
    (defined(__s390__) || defined(__s390x__) || defined(__zarch__)) || \
    defined(__vax__)
/*
 * The procesor natively handles unaligned loads, so just use memcpy()
 * and memcmp(), to enable those optimizations.
 *
 * XXX - are those all the x86 tests we need?
 * XXX - do we need to worry about ARMv1 through ARMv5, which didn't
 * support unaligned loads, and, if so, do we need to worry about all
 * of them, or just some of them, e.g. ARMv5?
 * XXX - are those the only 68k tests we need not to generated
 * unaligned accesses if the target is the 68000 or 68010?
 * XXX - are there any tests we don't need, because some definitions are for
 * compilers that also predefine the GCC symbols?
 * XXX - do we need to test for both 32-bit and 64-bit versions of those
 * architectures in all cases?
 */
#define UNALIGNED_MEMCPY(p, q, l)    memcpy((p), (q), (l))
#define UNALIGNED_MEMCMP(p, q, l)    memcmp((p), (q), (l))
#else
/*
 * The processor doesn't natively handle unaligned loads,
 * and the compiler might "helpfully" optimize memcpy()
 * and memcmp(), when handed pointers that would normally
 * be properly aligned, into sequences that assume proper
 * alignment.
 *
 * Do copies and compares of possibly-unaligned data by
 * calling routines that wrap memcpy() and memcmp(), to
 * prevent that optimization.
 */
extern void unaligned_memcpy(void *, const void *, size_t);
extern int unaligned_memcmp(const void *, const void *, size_t);
#define UNALIGNED_MEMCPY(p, q, l)    unaligned_memcpy((p), (q), (l))
#define UNALIGNED_MEMCMP(p, q, l)    unaligned_memcmp((p), (q), (l))
#endif

#endif  /* netdissect_h */
