#ifndef __KITESHIELD_OBFUSCATION_H
#define __KITESHIELD_OBFUSCATION_H

#include "common/include/defs.h"
#include "cipher/aes.h"

void obf_deobf_outer_key_aes(
    struct aes_key *old_key,
    struct aes_key *new_key,
    unsigned char *loader_bin,
    unsigned int loader_bin_size);

void obf_deobf_outer_key_des(
    struct des_key *old_key,
    struct des_key *new_key,
    unsigned char *loader_bin,
    unsigned int loader_bin_size);

void obf_deobf_outer_key_des3(
    struct des3_key *old_key,
    struct des3_key *new_key,
    unsigned char *loader_bin,
    unsigned int loader_bin_size);

void obf_deobf_outer_key_rc4(
    struct rc4_key *old_key,
    struct rc4_key *new_key,
    unsigned char *loader_bin,
    unsigned int loader_bin_size);


void obf_deobf_rt_info(
    struct runtime_info *rt_info);

#endif /* __KITESHIELD_OBFUSCATION_H */

