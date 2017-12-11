#pragma once
#ifndef _TYPES_H
#define _TYPES_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#if defined (_WIN32)
#include <windows.h>
#if defined (_BASETSD_H)
#else
typedef UINT8  uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
typedef INT8   int8_t;
typedef INT16  int16_t;
typedef INT32  int32_t;
typedef INT64  int64_t;
#endif
#endif // _WIN

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef struct pw
{
	u32 i[64];

	u32 pw_len;

} pw_t;

#if defined (_WIN32)
typedef LARGE_INTEGER     hc_timer_t;
#else
typedef struct timeval    hc_timer_t;
#endif

#include "ext_OpenCL.h"
#define EXEC_CACHE				128
#define EXPECTED_ITERATIONS		10000
#define SPEED_CACHE				128
#define PARAMCNT				64

typedef struct bitmap_ctx
{
	bool enabled;

	u32   bitmap_bits;
	u32   bitmap_nums;
	u32   bitmap_size;
	u32   bitmap_mask;
	u32   bitmap_shift1;
	u32   bitmap_shift2;

	u32  *bitmap_s1_a;
	u32  *bitmap_s1_b;
	u32  *bitmap_s1_c;
	u32  *bitmap_s1_d;
	u32  *bitmap_s2_a;
	u32  *bitmap_s2_b;
	u32  *bitmap_s2_c;
	u32  *bitmap_s2_d;

} bitmap_ctx_t;

typedef struct salt
{
	u32 salt_buf[64];
	u32 salt_buf_pc[64];

	u32 salt_len;
	u32 salt_len_pc;
	u32 salt_iter;
	u32 salt_iter2;
	u32 salt_sign[2];

	u32 keccak_mdlen;

	u32 digests_cnt;
	u32 digests_done;

	u32 digests_offset;

	u32 scrypt_N;
	u32 scrypt_r;
	u32 scrypt_p;

} salt_t;

typedef struct user
{
	char *user_name;
	u32   user_len;

} user_t;

typedef struct split
{
	// some hashes, like lm, are split. this id point to the other hash of the group

	int split_group;
	int split_neighbor;
	int split_origin;

} split_t;

typedef struct hashinfo
{
	user_t  *user;
	char    *orighash;
	split_t *split;

} hashinfo_t;

typedef struct hash
{
	void       *digest;
	salt_t     *salt;
	void       *esalt;
	void       *hook_salt; // additional salt info only used by the hook (host)
	int         cracked;
	hashinfo_t *hash_info;
	char       *pw_buf;
	int         pw_len;

} hash_t;

typedef struct hashes
{
	const char  *hashfile;

	u32          hashlist_mode;
	u32          hashlist_format;

	u32          digests_cnt;
	u32          digests_done;
	u32          digests_saved;

	void        *digests_buf;
	u32         *digests_shown;
	u32         *digests_shown_tmp;

	u32          salts_cnt;
	u32          salts_done;

	salt_t      *salts_buf;
	u32         *salts_shown;

	void        *esalts_buf;

	void        *hook_salts_buf;

	u32          hashes_cnt_orig;
	u32          hashes_cnt;
	hash_t      *hashes_buf;

	hashinfo_t **hash_info;

	u8          *out_buf; // allocates [HCBUFSIZ_LARGE];
	u8          *tmp_buf; // allocates [HCBUFSIZ_LARGE];

						  // selftest buffers

	void        *st_digests_buf;
	salt_t      *st_salts_buf;
	void        *st_esalts_buf;
	void        *st_hook_salts_buf;

} hashes_t;

typedef struct plain
{
	u32  salt_pos;
	u32  digest_pos;
	u32  hash_pos;
	u32  gidvid;
	u32  il_pos;

} plain_t;

typedef struct md5crypt_tmp
{
	u32 digest_buf[4];

} md5crypt_tmp_t;

typedef struct hashconfig
{
	char  separator;

	u32   hash_mode;
	u32   hash_type;
	u32   salt_type;
	u32   attack_exec;
	u64   opts_type;
	u32   kern_type;
	u32   dgst_size;
	u32   opti_type;
	u32   dgst_pos0;
	u32   dgst_pos1;
	u32   dgst_pos2;
	u32   dgst_pos3;

	bool  is_salted;

	bool  has_pure_kernel;
	bool  has_optimized_kernel;

	// sizes have to be size_t

	size_t  esalt_size;
	size_t  hook_salt_size;
	size_t  tmp_size;
	size_t  hook_size;

	// password length limit

	u32   pw_min;
	u32   pw_max;

	// salt length limit (generic hashes)

	u32   salt_min;
	u32   salt_max;

	int(*parse_func) (u8 *, u32, hash_t *);

	char *st_hash;
	char *st_pass;
} hashconfig_t;

typedef struct hc_md5_device_param
{
	cl_device_id    device;
	cl_device_type  device_type;
	cl_uint num_devices;

	u32     device_id;
	u32     platform_devices_id;   // for mapping with hms devices

	bool    skipped;
	bool    skipped_temp;

	u32     sm_major;
	u32     sm_minor;
	u32     kernel_exec_timeout;

	u8      pcie_bus;
	u8      pcie_device;
	u8      pcie_function;

	u32     device_processors;
	u64     device_maxmem_alloc;
	u64     device_global_mem;
	u32     device_maxclock_frequency;
	size_t  device_maxworkgroup_size;

	u32     vector_width;

	u32     kernel_threads_by_user;

	u32     kernel_threads_by_wgs_kernel1;
	u32     kernel_threads_by_wgs_kernel2;
	u32     kernel_threads_by_wgs_kernel3;

	u32     kernel_loops;
	u32     kernel_accel;
	u32     kernel_loops_min;
	u32     kernel_loops_max;
	u32     kernel_loops_min_sav; // the _sav are required because each -i iteration
	u32     kernel_loops_max_sav; // needs to recalculate the kernel_loops_min/max based on the current amplifier count
	u32     kernel_accel_min;
	u32     kernel_accel_max;
	u32     kernel_power;
	u32     hardware_power;

	size_t  size_pws;
	size_t  size_pws_amp;
	size_t  size_tmps;
	size_t  size_hooks;
	size_t  size_bfs;
	size_t  size_combs;
	size_t  size_rules;
	size_t  size_rules_c;
	size_t  size_root_css;
	size_t  size_markov_css;
	size_t  size_digests;
	size_t  size_salts;
	size_t  size_shown;
	size_t  size_results;
	size_t  size_plains;
	size_t  size_st_digests;
	size_t  size_st_salts;
	size_t  size_st_esalts;

	FILE   *combs_fp;
	pw_t   *combs_buf;

	void   *hooks_buf;

	pw_t   *pws_buf;
	u32     pws_cnt;

	u64     words_off;
	u64     words_done;

	u32     outerloop_pos;
	u32     outerloop_left;
	double  outerloop_msec;

	u64     innerloop_pos;
	u64     innerloop_left;

	u32     exec_pos;
	double  exec_msec[EXEC_CACHE];

	// workaround cpu spinning

	double  exec_us_prev1[EXPECTED_ITERATIONS];
	double  exec_us_prev2[EXPECTED_ITERATIONS];
	double  exec_us_prev3[EXPECTED_ITERATIONS];
	double  exec_us_prev4[EXPECTED_ITERATIONS];
	double  exec_us_prev_init2[EXPECTED_ITERATIONS];
	double  exec_us_prev_loop2[EXPECTED_ITERATIONS];

	// this is "current" speed

	u32     speed_pos;
	u64     speed_cnt[SPEED_CACHE];
	double  speed_msec[SPEED_CACHE];

	hc_timer_t timer_speed;

	// device specific attributes starting

	char   *device_name;
	char   *device_vendor;
	char   *device_version;
	char   *driver_version;
	char   *device_opencl_version;

	bool    is_rocm;

	double  nvidia_spin_damp;

	cl_uint num_platforms;
	cl_platform_id* platforms;

	cl_uint  device_vendor_id;
	cl_uint  platform_vendor_id;

	cl_kernel  kernel1;
	cl_kernel  kernel2;
	cl_kernel  kernel3;

	cl_context context;

	cl_program program;

	cl_command_queue command_queue;

	cl_mem  d_pws_buf;
	cl_mem  d_pws_amp_buf;
	cl_mem	d_tmps;
	cl_mem  d_bitmap_s1_a;
	cl_mem  d_bitmap_s1_b;
	cl_mem  d_bitmap_s1_c;
	cl_mem  d_bitmap_s1_d;
	cl_mem  d_bitmap_s2_a;
	cl_mem  d_bitmap_s2_b;
	cl_mem  d_bitmap_s2_c;
	cl_mem  d_bitmap_s2_d;
	cl_mem  d_plain_bufs;
	cl_mem  d_digests_buf;
	cl_mem  d_hashes_shown;
	cl_mem  d_salt_bufs;
	cl_mem  d_return_buf;

	void   *kernel_params[PARAMCNT];

	u32     kernel_params_buf32[PARAMCNT];
	u64     kernel_params_buf64[PARAMCNT];

} hc_md5_device_param_t;

typedef struct opencl_ctx
{
	bool                enabled;

	void               *ocl;

	cl_uint             platforms_cnt;
	cl_platform_id     *platforms;
	char              **platforms_vendor;
	char              **platforms_name;
	char              **platforms_version;
	bool               *platforms_skipped;

	cl_uint             platform_devices_cnt;
	cl_device_id       *platform_devices;

	u32                 devices_cnt;
	u32                 devices_active;

	hc_md5_device_param_t  *devices_param;

	u32                 hardware_power_all;

	u32                 kernel_power_all;
	u64                 kernel_power_final; // we save that so that all divisions are done from the same base

	u32                 opencl_platforms_filter;
	u32                 devices_filter;
	cl_device_type      device_types_filter;

	double              target_msec;

	bool                need_adl;
	bool                need_nvml;
	bool                need_nvapi;
	bool                need_xnvctrl;
	bool                need_sysfs;

	int                 comptime;

	int                 force_jit_compilation;

} opencl_ctx_t;

#endif