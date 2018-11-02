/*
 * Copyright (c) 2001
 *    Fortress Technologies, Inc.  All rights reserved.
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

#include <string.h>

#include "netdissect.h"

#include "extract.h"

#include "cpack.h"

/*
 * The radio capture header precedes the 802.11 header.
 *
 * Note well: all radiotap fields are little-endian.
 */
struct ieee80211_radiotap_header {
    nd_uint8_t    it_version;    /* Version 0. Only increases
                     * for drastic changes,
                     * introduction of compatible
                     * new fields does not count.
                     */
    nd_uint8_t    it_pad;
    nd_uint16_t    it_len;        /* length of the whole
                     * header in bytes, including
                     * it_version, it_pad,
                     * it_len, and data fields.
                     */
    nd_uint32_t    it_present;    /* A bitmap telling which
                     * fields are present. Set bit 31
                     * (0x80000000) to extend the
                     * bitmap by another 32 bits.
                     * Additional extensions are made
                     * by setting bit 31.
                     */
};

/* Name                                 Data type       Units
 * ----                                 ---------       -----
 *
 * IEEE80211_RADIOTAP_DBM_ANTSIGNAL     int8_t          decibels from
 *                                                      one milliwatt (dBm)
 *
 *      RF signal power at the antenna, decibel difference from
 *      one milliwatt.
 *
 * IEEE80211_RADIOTAP_VENDOR_NAMESPACE
 *                    uint8_t  OUI[3]
 *                                   uint8_t  subspace
 *                                   uint16_t length
 *
 *     The Vendor Namespace Field contains three sub-fields. The first
 *     sub-field is 3 bytes long. It contains the vendor's IEEE 802
 *     Organizationally Unique Identifier (OUI). The fourth byte is a
 *     vendor-specific "namespace selector."
 *
 */
enum ieee80211_radiotap_type {
    IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
    IEEE80211_RADIOTAP_NAMESPACE = 29,
    IEEE80211_RADIOTAP_VENDOR_NAMESPACE = 30,
    IEEE80211_RADIOTAP_EXT = 31
};

static int8_t awss_parse_radiotap_field(struct cpack_state *s, uint32_t bit, uint8_t *flagsp, uint32_t presentflags)
{
    int rc;

    switch (bit) {
        case IEEE80211_RADIOTAP_DBM_ANTSIGNAL: {
            int8_t rssi_dbm;
            rc = cpack_int8(s, &rssi_dbm);
            if (rc != 0)
                goto trunc;
            //return rssi_dbm > 0 ? rssi_dbm - 128 : rssi_dbm;
            return rssi_dbm > 0 ? rssi_dbm - 256: rssi_dbm;
            break;
        }

    default:
        /* this bit indicates a field whose
         * size we do not know, so we cannot
         * proceed.  Just print the bit number.
         */
        if (bit <= 14 || (bit >= 18 && bit < IEEE80211_RADIOTAP_NAMESPACE))
            break;
        return -1;
    }

trunc:
    return -1;
}


static int8_t print_in_radiotap_namespace(struct cpack_state *s, uint8_t *flags,
                                       uint32_t presentflags, int bit0)
{
#define    BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define    BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define    BITNO_8(x) (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define    BITNO_4(x) (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define    BITNO_2(x) (((x) & 2) ? 1 : 0)
    uint32_t present, next_present;
    int bitno;
    enum ieee80211_radiotap_type bit;
    int8_t rssi;

    for (present = presentflags; present; present = next_present) {
        /*
         * Clear the least significant bit that is set.
         */
        next_present = present & (present - 1);

        /*
         * Get the bit number, within this presence word,
         * of the remaining least significant bit that
         * is set.
         */
        bitno = BITNO_32(present ^ next_present);

        /*
         * Stop if this is one of the "same meaning
         * in all presence flags" bits.
         */
        if (bitno >= IEEE80211_RADIOTAP_NAMESPACE)
            break;

        /*
         * Get the radiotap bit number of that bit.
         */
        bit = (enum ieee80211_radiotap_type)(bit0 + bitno);

        rssi = awss_parse_radiotap_field(s, bit, flags, presentflags);
        if (rssi < -1)
            return rssi;
    }

    return -1;
}

int awss_parse_ieee802_11_radio_header(const char *p, int caplen, int8_t *rssi)
{
#define    BIT(n)    (1U << n)
#define    IS_EXTENDED(__p)    \
        (EXTRACT_LE_U_4(__p) & BIT(IEEE80211_RADIOTAP_EXT)) != 0

    struct cpack_state cpacker;
    const struct ieee80211_radiotap_header *hdr;
    uint32_t presentflags;
    const nd_uint32_t *presentp, *last_presentp;
    int vendor_namespace;
    uint8_t vendor_oui[3];
    uint8_t vendor_subnamespace;
    uint16_t skip_length;
    int bit0;
    u_int len;
    uint8_t flags;

    if (caplen < sizeof(*hdr))
        return -1;

    hdr = (const struct ieee80211_radiotap_header *)p;

    len = EXTRACT_LE_U_2(hdr->it_len);
    if (len < sizeof(*hdr))
        return -1;

    /*
     * If we don't have the entire radiotap header, just give up.
     */
    if (caplen < len)
        return -1;

    cpack_init(&cpacker, (const uint8_t *)hdr, len); /* align against header start */
    cpack_advance(&cpacker, sizeof(*hdr)); /* includes the 1st bitmap */
    for (last_presentp = &hdr->it_present;
         (const long)(last_presentp + 1) <= (const long)(p + len) &&
         IS_EXTENDED(last_presentp);
         last_presentp++)
      cpack_advance(&cpacker, sizeof(hdr->it_present)); /* more bitmaps */

    /* are there more bitmap extensions than bytes in header? */
    if ((const long)(last_presentp + 1) > (const long)(p + len))
        return -1;

    /*
     * Start out at the beginning of the default radiotap namespace.
     */
    bit0 = 0;
    vendor_namespace = 0;
    memset(vendor_oui, 0, 3);
    vendor_subnamespace = 0;
    skip_length = 0;
    /* Assume no flags */
    flags = 0;
    for (presentp = &hdr->it_present; presentp <= last_presentp;
        presentp++) {
        presentflags = EXTRACT_LE_U_4(presentp);

        /*
         * If this is a vendor namespace, we don't handle it.
         */
        if (vendor_namespace) {
            /*
             * Skip past the stuff we don't understand.
             * If we add support for any vendor namespaces,
             * it'd be added here; use vendor_oui and
             * vendor_subnamespace to interpret the fields.
             */
            if (cpack_advance(&cpacker, skip_length) != 0) {
                /*
                 * Ran out of space in the packet.
                 */
                break;
            }

            /*
             * We've skipped it all; nothing more to
             * skip.
             */
            skip_length = 0;
        } else {
            int8_t rssi_dbm = print_in_radiotap_namespace(&cpacker, &flags, presentflags, bit0);
            if (rssi_dbm < -1) {
                /*
                 * Fatal error - can't process anything
                 * more in the radiotap header.
                 */
                *rssi = rssi_dbm;
                break;
            }
        }

        /*
         * Handle the namespace switch bits; we've already handled
         * the extension bit in all but the last word above.
         */
        switch (presentflags &
            (BIT(IEEE80211_RADIOTAP_NAMESPACE)|BIT(IEEE80211_RADIOTAP_VENDOR_NAMESPACE))) {

        case 0:
            /*
             * We're not changing namespaces.
             * advance to the next 32 bits in the current
             * namespace.
             */
            bit0 += 32;
            break;

        case BIT(IEEE80211_RADIOTAP_NAMESPACE):
            /*
             * We're switching to the radiotap namespace.
             * Reset the presence-bitmap index to 0, and
             * reset the namespace to the default radiotap
             * namespace.
             */
            bit0 = 0;
            vendor_namespace = 0;
            memset(vendor_oui, 0, 3);
            vendor_subnamespace = 0;
            skip_length = 0;
            break;

        case BIT(IEEE80211_RADIOTAP_VENDOR_NAMESPACE):
            /*
             * We're switching to a vendor namespace.
             * Reset the presence-bitmap index to 0,
             * note that we're in a vendor namespace,
             * and fetch the fields of the Vendor Namespace
             * item.
             */
            bit0 = 0;
            vendor_namespace = 1;
            if ((cpack_align_and_reserve(&cpacker, 2)) == NULL)
                break;
            if (cpack_uint8(&cpacker, &vendor_oui[0]) != 0)
                break;
            if (cpack_uint8(&cpacker, &vendor_oui[1]) != 0)
                break;
            if (cpack_uint8(&cpacker, &vendor_oui[2]) != 0)
                break;
            if (cpack_uint8(&cpacker, &vendor_subnamespace) != 0)
                break;
            if (cpack_uint16(&cpacker, &skip_length) != 0)
                break;
            break;

        default:
            /*
             * Illegal combination.  The behavior in this
             * case is undefined by the radiotap spec; we
             * just ignore both bits.
             */
            break;
        }
    }

    return 0;
#undef BITNO_32
#undef BITNO_16
#undef BITNO_8
#undef BITNO_4
#undef BITNO_2
#undef BIT
}

/*
 * For DLT_IEEE802_11_RADIO; like DLT_IEEE802_11, but with an extra
 * header, containing information such as radio information.
 */
