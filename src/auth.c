#define __STDC_WANT_LIB_EXT1__ 1
#include "rt.h"

#include <CommonCrypto/CommonCryptoError.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <stdlib.h>
#include <string.h>

#define MIN_ROUNDS 200000u

static int derive(const struct pwhash *h, const char *pw, unsigned char *out)
{
    return CCKeyDerivationPBKDF(kCCPBKDF2, pw, strlen(pw), h->salt, sizeof h->salt,
                                kCCPRFHmacAlgSHA256, h->rounds, out, sizeof h->key)
           == kCCSuccess ? 0 : -1;
}

int pw_set(struct pwhash *h, const char *pw)
{
    arc4random_buf(h->salt, sizeof h->salt);
    /* Calibrated so one check costs ~250 ms on this machine. */
    h->rounds = CCCalibratePBKDF(kCCPBKDF2, strlen(pw), sizeof h->salt,
                                 kCCPRFHmacAlgSHA256, sizeof h->key, 250);
    if (h->rounds < MIN_ROUNDS)
        h->rounds = MIN_ROUNDS;
    return derive(h, pw, h->key);
}

int pw_check(const struct pwhash *h, const char *pw)
{
    unsigned char k[sizeof h->key];
    int ok = derive(h, pw, k) == 0 && timingsafe_bcmp(k, h->key, sizeof k) == 0;
    memset_s(k, sizeof k, 0, sizeof k);
    return ok;
}
