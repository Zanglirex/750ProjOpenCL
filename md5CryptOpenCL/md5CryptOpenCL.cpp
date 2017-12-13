// md5CryptOpenCL.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "types.h"
#include "md5_funcs.h"
#include "bitmap.h"
#include "clinfo.h"

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif

#ifdef __unix__
	#define OS_Windows 0
	#define MAX_PATH 260
	#include <unistd.h>
	#include <ifstream>
#elif defined(_WIN32) || defined(WIN32)
	#define OS_Windows 1
	#include <Windows.h>
	#include <fstream>
	using namespace std;
#endif

#define MAX_SOURCE_SIZE (0x100000)
#define MIN(a,b) (((a) < (b)) ? (a) : (b))

void get_cur_path(char* pwd) {
	#ifdef __unix__
		getcwd(pwd, MAX_PATH);
	#elif defined(_WIN32)
		TCHAR temp_pwd[MAX_PATH];
		GetCurrentDirectory(sizeof(temp_pwd), temp_pwd);
		snprintf(pwd, sizeof(temp_pwd) - 1, "%ws", temp_pwd);
	#endif
}

static int get_kernel_threads(hc_md5_device_param_t *md5_controller, cl_kernel kernel, u32 *result)
{
	int CL_rc;
	size_t work_group_size;
	size_t compile_work_group_size[3];
	u32 kernel_threads = md5_controller->kernel_threads_by_user;

	CL_rc = clGetKernelWorkGroupInfo(kernel, md5_controller->device, CL_KERNEL_WORK_GROUP_SIZE, sizeof(work_group_size), &work_group_size, NULL);
	if (CL_rc == -1) return -1;

	CL_rc = clGetKernelWorkGroupInfo(kernel, md5_controller->device, CL_KERNEL_COMPILE_WORK_GROUP_SIZE, sizeof(compile_work_group_size), &compile_work_group_size, NULL);
	if (CL_rc == -1) return -1;

	if (work_group_size > 0){
		kernel_threads = (u32)MIN(kernel_threads, work_group_size);
	}

	if (compile_work_group_size[0] > 0){
		kernel_threads = (u32)MIN(kernel_threads, compile_work_group_size[0]);
	}

	*result = kernel_threads;
	return 0;
}

const char *getErrorString(cl_int error)
{
	switch (error) {
		// run-time and JIT compiler errors
	case 0: return "CL_SUCCESS";
	case -1: return "CL_DEVICE_NOT_FOUND";
	case -2: return "CL_DEVICE_NOT_AVAILABLE";
	case -3: return "CL_COMPILER_NOT_AVAILABLE";
	case -4: return "CL_MEM_OBJECT_ALLOCATION_FAILURE";
	case -5: return "CL_OUT_OF_RESOURCES";
	case -6: return "CL_OUT_OF_HOST_MEMORY";
	case -7: return "CL_PROFILING_INFO_NOT_AVAILABLE";
	case -8: return "CL_MEM_COPY_OVERLAP";
	case -9: return "CL_IMAGE_FORMAT_MISMATCH";
	case -10: return "CL_IMAGE_FORMAT_NOT_SUPPORTED";
	case -11: return "CL_BUILD_PROGRAM_FAILURE";
	case -12: return "CL_MAP_FAILURE";
	case -13: return "CL_MISALIGNED_SUB_BUFFER_OFFSET";
	case -14: return "CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST";
	case -15: return "CL_COMPILE_PROGRAM_FAILURE";
	case -16: return "CL_LINKER_NOT_AVAILABLE";
	case -17: return "CL_LINK_PROGRAM_FAILURE";
	case -18: return "CL_DEVICE_PARTITION_FAILED";
	case -19: return "CL_KERNEL_ARG_INFO_NOT_AVAILABLE";

		// compile-time errors
	case -30: return "CL_INVALID_VALUE";
	case -31: return "CL_INVALID_DEVICE_TYPE";
	case -32: return "CL_INVALID_PLATFORM";
	case -33: return "CL_INVALID_DEVICE";
	case -34: return "CL_INVALID_CONTEXT";
	case -35: return "CL_INVALID_QUEUE_PROPERTIES";
	case -36: return "CL_INVALID_COMMAND_QUEUE";
	case -37: return "CL_INVALID_HOST_PTR";
	case -38: return "CL_INVALID_MEM_OBJECT";
	case -39: return "CL_INVALID_IMAGE_FORMAT_DESCRIPTOR";
	case -40: return "CL_INVALID_IMAGE_SIZE";
	case -41: return "CL_INVALID_SAMPLER";
	case -42: return "CL_INVALID_BINARY";
	case -43: return "CL_INVALID_BUILD_OPTIONS";
	case -44: return "CL_INVALID_PROGRAM";
	case -45: return "CL_INVALID_PROGRAM_EXECUTABLE";
	case -46: return "CL_INVALID_KERNEL_NAME";
	case -47: return "CL_INVALID_KERNEL_DEFINITION";
	case -48: return "CL_INVALID_KERNEL";
	case -49: return "CL_INVALID_ARG_INDEX";
	case -50: return "CL_INVALID_ARG_VALUE";
	case -51: return "CL_INVALID_ARG_SIZE";
	case -52: return "CL_INVALID_KERNEL_ARGS";
	case -53: return "CL_INVALID_WORK_DIMENSION";
	case -54: return "CL_INVALID_WORK_GROUP_SIZE";
	case -55: return "CL_INVALID_WORK_ITEM_SIZE";
	case -56: return "CL_INVALID_GLOBAL_OFFSET";
	case -57: return "CL_INVALID_EVENT_WAIT_LIST";
	case -58: return "CL_INVALID_EVENT";
	case -59: return "CL_INVALID_OPERATION";
	case -60: return "CL_INVALID_GL_OBJECT";
	case -61: return "CL_INVALID_BUFFER_SIZE";
	case -62: return "CL_INVALID_MIP_LEVEL";
	case -63: return "CL_INVALID_GLOBAL_WORK_SIZE";
	case -64: return "CL_INVALID_PROPERTY";
	case -65: return "CL_INVALID_IMAGE_DESCRIPTOR";
	case -66: return "CL_INVALID_COMPILER_OPTIONS";
	case -67: return "CL_INVALID_LINKER_OPTIONS";
	case -68: return "CL_INVALID_DEVICE_PARTITION_COUNT";

		// extension errors
	case -1000: return "CL_INVALID_GL_SHAREGROUP_REFERENCE_KHR";
	case -1001: return "CL_PLATFORM_NOT_FOUND_KHR";
	case -1002: return "CL_INVALID_D3D10_DEVICE_KHR";
	case -1003: return "CL_INVALID_D3D10_RESOURCE_KHR";
	case -1004: return "CL_D3D10_RESOURCE_ALREADY_ACQUIRED_KHR";
	case -1005: return "CL_D3D10_RESOURCE_NOT_ACQUIRED_KHR";
	default: return "Unknown OpenCL error";
	}
}

void load_md5_hashconfig(hashconfig_t * md5_hashconfig) {
	md5_hashconfig->hash_type = 2;		// HASH_TYPE_MD5;
	md5_hashconfig->salt_type = 2;		// SALT_TYPE_EMBEDDED;
	md5_hashconfig->attack_exec = 10;	//ATTACK_EXEC_OUTSIDE_KERNEL;
	md5_hashconfig->opts_type = 512;	//OPTS_TYPE_PT_GENERATE_LE;
	md5_hashconfig->kern_type = 500;	//KERN_TYPE_MD5CRYPT;
	md5_hashconfig->dgst_size = 16;		//DGST_SIZE_4_4;
	md5_hashconfig->parse_func = md5crypt_parse_hash;
	md5_hashconfig->opti_type = 2;		//OPTI_TYPE_ZERO_BYTE;
	md5_hashconfig->dgst_pos0 = 0;
	md5_hashconfig->dgst_pos1 = 1;
	md5_hashconfig->dgst_pos2 = 2;
	md5_hashconfig->dgst_pos3 = 3;
	// this is a password + hash mix that can be tested
	//md5_hashconfig->st_hash = "$1$38652870$DUjsu4TTlTsOe/xxZ05uf/"; //ST_HASH_00500;
	//md5_hashconfig->st_pass = "hashcat";//ST_PASS_HASHCAT_PLAIN;
	md5_hashconfig->tmp_size = sizeof(md5crypt_tmp_t);
	md5_hashconfig->pw_max = 15;
	md5_hashconfig->is_salted = true;
}

void setup_device(hc_md5_device_param_t* md5_controller) {
	cl_uint vector_width = 1;
	cl_int ret;

	//get platform with device info
	clGetPlatformIDs(0, NULL, &md5_controller->num_platforms);
	printf("num_platforms = %d\n", md5_controller->num_platforms);
	md5_controller->platforms = NULL;
	md5_controller->platforms = (cl_platform_id*)malloc(md5_controller->num_platforms * sizeof(cl_platform_id));

	ret = clGetPlatformIDs(md5_controller->num_platforms, md5_controller->platforms, NULL);
	printf("ret at %d is %s\n", __LINE__, getErrorString(ret));

	ret = clGetDeviceIDs(md5_controller->platforms[1], CL_DEVICE_TYPE_ALL, 1,
		&md5_controller->device, &md5_controller->num_devices);
	printf("ret at %d is %s\n", __LINE__, getErrorString(ret));
	// Create an OpenCL context
	md5_controller->context = clCreateContext(NULL, 1, &md5_controller->device, NULL, NULL, &ret);
	printf("ret at %d is %s\n", __LINE__, getErrorString(ret));

	// Create a command queue
	md5_controller->command_queue = clCreateCommandQueue(md5_controller->context, md5_controller->device, 0, &ret);
	printf("ret at %d is %s\n", __LINE__, getErrorString(ret));

	//processors on the device
	cl_uint device_processors = 1;
	ret = clGetDeviceInfo(md5_controller->device, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(device_processors), &device_processors, NULL);
	if (ret != 0) printf("ret at %d is %s\n", __LINE__, getErrorString(ret));
	md5_controller->device_processors = device_processors;

	//vector width of the device
	ret = clGetDeviceInfo(md5_controller->device, CL_DEVICE_PREFERRED_VECTOR_WIDTH_INT, sizeof(vector_width), &vector_width, NULL);
	if (ret != 0) printf("ret at %d is %s\n", __LINE__, getErrorString(ret));
	if (vector_width > 16) vector_width = 16;
	md5_controller->vector_width = vector_width;

	//device_type
	cl_device_type device_type;
	ret = clGetDeviceInfo(md5_controller->device, CL_DEVICE_TYPE, sizeof(device_type), &device_type, NULL);
	if (ret != 0) printf("ret at %d is %s\n", __LINE__, getErrorString(ret));
	md5_controller->device_type = device_type;

	md5_controller->kernel_accel_min = 1;
	md5_controller->kernel_accel_max = 1024;

	const u32 kernel_threads = 8;
	md5_controller->kernel_threads_by_user = kernel_threads;
	md5_controller->hardware_power = device_processors* kernel_threads;
}

int file_get_line(FILE *fp, char *line_buf){
	int line_len = 0;

	while (!feof(fp)){
		const int c = fgetc(fp);

		if (c == EOF) break;
		line_buf[line_len] = (char)c;
		line_len++;
		if (line_len == 100) line_len--;
		if (c == '\n') break;
	}

	if (line_len == 0) return 0;

	while (line_len){
		if (line_buf[line_len - 1] == '\n'){
			line_len--;
			continue;
		}
		if (line_buf[line_len - 1] == '\r'){
			line_len--;
			continue;
		}
		break;
	}
	line_buf[line_len] = 0;
	return (line_len);
}

void load_kernel_source(char* filename, char* source_str, size_t* source_size) {
	FILE *fp;

	fopen_s(&fp, filename, "r");
	if (!fp) {
		fprintf(stderr, "Failed to load kernel.\n");
		exit(1);
	}
	*source_size = fread(source_str, 1, MAX_SOURCE_SIZE, fp);
	fclose(fp);
	printf("kernel loading done\n");
}

void build_program(hc_md5_device_param_t* md5_controller, char* filename) {
	char build_opts[1024] = { 0 };
	char *source_str = (char*)malloc(MAX_SOURCE_SIZE);
	size_t source_size;
	cl_int ret = 0;

	//OpenCL includes argument
	char pwd[MAX_PATH];
	get_cur_path(pwd);
	printf("Working Directory is %s\n", pwd);

	load_kernel_source(filename, source_str, &source_size);

	// Create a program from the kernel source
	md5_controller->program = clCreateProgramWithSource(md5_controller->context, 1,
		(const char **)&source_str, (const size_t *)&source_size, &ret);
	printf("ret at %d is %s\n", __LINE__, getErrorString(ret));

	snprintf(build_opts, sizeof(build_opts) - 1, "-I \"%s\" -D DGST_R0=%u -D DGST_R1=%u -D DGST_R2=%u -D DGST_R3=%u -D DGST_ELEM=%u -D _unroll -w", pwd, 0, 1, 2, 3, 16 / 4);
	//snprintf(build_opts_new, sizeof(build_opts_new) - 1, "%s -D VENDOR_ID=%u -D CUDA_ARCH=%u -D AMD_ROCM=%u -D VECT_SIZE=%u -D DEVICE_TYPE=%u -D DGST_R0=%u -D DGST_R1=%u -D DGST_R2=%u -D DGST_R3=%u -D DGST_ELEM=%u -D KERN_TYPE=%u -D _unroll -w", build_opts,md5_controller->platform_vendor_id, (md5_controller->sm_major * 100) +md5_controller->sm_minor,md5_controller->is_rocm,md5_controller->vector_width, (u32)md5_controller->device_type, hashconfig->dgst_pos0, hashconfig->dgst_pos1, hashconfig->dgst_pos2, hashconfig->dgst_pos3, hashconfig->dgst_size / 4, hashconfig->kern_type);
	//printf("build_opts is %s\n", build_opts);

	// Build the program
	ret = clBuildProgram(md5_controller->program, 1, &md5_controller->device, build_opts, NULL, NULL);
	printf("ret at %d is %s\n", __LINE__, getErrorString(ret));
	if (ret != CL_SUCCESS) {
		char *fail_log;
		size_t len;
		clGetProgramBuildInfo(md5_controller->program, md5_controller->device, CL_PROGRAM_BUILD_LOG, 0, NULL, &len);
		fail_log = (char*)calloc(len, sizeof(char));
		clGetProgramBuildInfo(md5_controller->program, md5_controller->device, CL_PROGRAM_BUILD_LOG, len, fail_log, NULL);
		printf("%s\n", fail_log);
		free(fail_log);
	}

	free(source_str);
	printf("done building program\n");
}

void set_controller_sizes(hc_md5_device_param_t* md5_controller, hashconfig_t* md5_hashconfig, hashes_t* md5_hashes) {
	md5_controller->size_plains = (size_t)md5_hashes->digests_cnt * sizeof(plain_t);
	md5_controller->size_salts = (size_t)md5_hashes->salts_cnt * sizeof(salt_t);
	md5_controller->size_shown = (size_t)md5_hashes->digests_cnt * sizeof(u32);
	md5_controller->size_digests = (size_t)md5_hashes->digests_cnt * (size_t)md5_hashconfig->dgst_size;
	md5_controller->size_results = sizeof(u32);
	md5_controller->size_pws = 4;
	md5_controller->size_pws_amp = 4;
	md5_controller->size_tmps = 4;
	//TODO insert accelleration from opencl.c line 3900 or so
}

void setup_hashes(hashconfig_t* md5_hashconfig,hashes_t* md5_hashes) {
	u32 hashes_available = 0;
	hash_t *hashes_buf = NULL;
	void *digests_buf = NULL;
	salt_t *salts_buf = NULL;
	char* hashfile = "hashes.txt";
	FILE * fp = NULL;
	int ch = 0;
	int line_num = 0;
	char* line_buf = (char*) calloc(100, sizeof(char));
	u32 hash_size = (u32)strlen("$1$38652870$DUjsu4TTlTsOe/xxZ05uf/"); //example hash

	fopen_s(&fp, hashfile, "rb");
	while (!feof(fp)) {
		ch = fgetc(fp);
		if (ch == '\n')
		{
			hashes_available++;
		}
	}
	fclose(fp);
	printf("Read %d hashes from %s\n", hashes_available, hashfile);
	md5_hashes->hashes_cnt = hashes_available;
	md5_hashes->digests_cnt = hashes_available;
	md5_hashes->salts_cnt = hashes_available;


	hashes_buf = (hash_t*)calloc(hashes_available, sizeof(hash_t));
	digests_buf = calloc(hashes_available, md5_hashconfig->dgst_size);
	salts_buf = (salt_t*)calloc(hashes_available, sizeof(salt_t));

	for (u32 hash_pos = 0; hash_pos < hashes_available; hash_pos++) {
		hashes_buf[hash_pos].digest = ((char*)digests_buf) + (hash_pos* md5_hashconfig->dgst_size);
		hashes_buf[hash_pos].salt = &salts_buf[hash_pos];
	}

	md5_hashes->hashes_buf = hashes_buf;
	md5_hashes->digests_buf = digests_buf;
	md5_hashes->salts_buf = salts_buf;


	fopen_s(&fp, hashfile, "rb");
	while (!feof(fp)) {
		int line_len = file_get_line(fp, line_buf);
		if (line_len > 10) { //should be about 34 though
			ch = md5_hashconfig->parse_func((u8*)line_buf, hash_size, &hashes_buf[line_num]);
			if (ch != 0) printf("Something went wrong with the parsing function at line %d\n", __LINE__);
		}
		line_num++;
	}
	fclose(fp);

	//md5_hashconfig->parse_func((u8*)md5_hashconfig->st_hash, (u32)strlen(md5_hashconfig->st_hash), md5_hashes->hashes_buf);

	free(line_buf);
}

int createBuffers(hc_md5_device_param_t* md5_controller, bitmap_ctx_t* bitmap_ctx, hashes_t* md5_hashes) {
	cl_int ret;

	/**
	* global buffers
	*/

	md5_controller->d_pws_buf = clCreateBuffer(md5_controller->context, CL_MEM_READ_ONLY, md5_controller->size_pws, NULL, &ret);        if (ret == -1) return -1;
	md5_controller->d_pws_amp_buf = clCreateBuffer(md5_controller->context, CL_MEM_READ_ONLY, md5_controller->size_pws_amp, NULL, &ret);    if (ret == -1) return -1;
	md5_controller->d_tmps = clCreateBuffer(md5_controller->context, CL_MEM_READ_WRITE, md5_controller->size_tmps, NULL, &ret);           if (ret == -1) return -1;
	md5_controller->d_bitmap_s1_a = clCreateBuffer(md5_controller->context, CL_MEM_READ_ONLY, bitmap_ctx->bitmap_size, NULL, &ret);    if (ret == -1) return -1;
	md5_controller->d_bitmap_s1_b = clCreateBuffer(md5_controller->context, CL_MEM_READ_ONLY, bitmap_ctx->bitmap_size, NULL, &ret);    if (ret == -1) return -1;
	md5_controller->d_bitmap_s1_c = clCreateBuffer(md5_controller->context, CL_MEM_READ_ONLY, bitmap_ctx->bitmap_size, NULL, &ret);    if (ret == -1) return -1;
	md5_controller->d_bitmap_s1_d = clCreateBuffer(md5_controller->context, CL_MEM_READ_ONLY, bitmap_ctx->bitmap_size, NULL, &ret);    if (ret == -1) return -1;
	md5_controller->d_bitmap_s2_a = clCreateBuffer(md5_controller->context, CL_MEM_READ_ONLY, bitmap_ctx->bitmap_size, NULL, &ret);    if (ret == -1) return -1;
	md5_controller->d_bitmap_s2_b = clCreateBuffer(md5_controller->context, CL_MEM_READ_ONLY, bitmap_ctx->bitmap_size, NULL, &ret);    if (ret == -1) return -1;
	md5_controller->d_bitmap_s2_c = clCreateBuffer(md5_controller->context, CL_MEM_READ_ONLY, bitmap_ctx->bitmap_size, NULL, &ret);    if (ret == -1) return -1;
	md5_controller->d_bitmap_s2_d = clCreateBuffer(md5_controller->context, CL_MEM_READ_ONLY, bitmap_ctx->bitmap_size, NULL, &ret);    if (ret == -1) return -1;
	md5_controller->d_plain_bufs = clCreateBuffer(md5_controller->context, CL_MEM_READ_WRITE, md5_controller->size_plains, NULL, &ret);     if (ret == -1) return -1;
	md5_controller->d_digests_buf = clCreateBuffer(md5_controller->context, CL_MEM_READ_ONLY, md5_controller->size_digests, NULL, &ret);    if (ret == -1) return -1;
	md5_controller->d_hashes_shown = clCreateBuffer(md5_controller->context, CL_MEM_READ_WRITE, md5_controller->size_shown, NULL, &ret);  if (ret == -1) return -1;
	md5_controller->d_salt_bufs = clCreateBuffer(md5_controller->context, CL_MEM_READ_ONLY, md5_controller->size_salts, NULL, &ret);      if (ret == -1) return -1;
	md5_controller->d_return_buf = clCreateBuffer(md5_controller->context, CL_MEM_READ_WRITE, md5_controller->size_results, NULL, &ret);         if (ret == -1) return -1;

	ret = clEnqueueWriteBuffer(md5_controller->command_queue,md5_controller->d_bitmap_s1_a, CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s1_a, 0, NULL, NULL); if (ret == -1) return -1;
	ret = clEnqueueWriteBuffer(md5_controller->command_queue,md5_controller->d_bitmap_s1_b, CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s1_b, 0, NULL, NULL); if (ret == -1) return -1;
	ret = clEnqueueWriteBuffer(md5_controller->command_queue,md5_controller->d_bitmap_s1_c, CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s1_c, 0, NULL, NULL); if (ret == -1) return -1;
	ret = clEnqueueWriteBuffer(md5_controller->command_queue,md5_controller->d_bitmap_s1_d, CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s1_d, 0, NULL, NULL); if (ret == -1) return -1;
	ret = clEnqueueWriteBuffer(md5_controller->command_queue,md5_controller->d_bitmap_s2_a, CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s2_a, 0, NULL, NULL); if (ret == -1) return -1;
	ret = clEnqueueWriteBuffer(md5_controller->command_queue,md5_controller->d_bitmap_s2_b, CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s2_b, 0, NULL, NULL); if (ret == -1) return -1;
	ret = clEnqueueWriteBuffer(md5_controller->command_queue,md5_controller->d_bitmap_s2_c, CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s2_c, 0, NULL, NULL); if (ret == -1) return -1;
	ret = clEnqueueWriteBuffer(md5_controller->command_queue,md5_controller->d_bitmap_s2_d, CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s2_d, 0, NULL, NULL); if (ret == -1) return -1;
	ret = clEnqueueWriteBuffer(md5_controller->command_queue,md5_controller->d_digests_buf, CL_TRUE, 0, md5_controller->size_digests, md5_hashes->digests_buf, 0, NULL, NULL); if (ret == -1) return -1;
	ret = clEnqueueWriteBuffer(md5_controller->command_queue,md5_controller->d_salt_bufs, CL_TRUE, 0, md5_controller->size_salts, md5_hashes->salts_buf, 0, NULL, NULL); if (ret == -1) return -1;

	return 0;
}

void load_controller_arg_array(hc_md5_device_param_t* md5_controller, bitmap_ctx_t* bitmap) {
	/**
	* kernel args
	*/

	md5_controller->kernel_params_buf32[15] = bitmap->bitmap_mask;
	md5_controller->kernel_params_buf32[16] = bitmap->bitmap_shift1;
	md5_controller->kernel_params_buf32[17] = bitmap->bitmap_shift2;
	md5_controller->kernel_params_buf32[18] = 0; // salt_pos
	md5_controller->kernel_params_buf32[19] = 0; // loop_pos
	md5_controller->kernel_params_buf32[20] = 0; // loop_cnt
	md5_controller->kernel_params_buf32[21] = 0; // digests_cnt
	md5_controller->kernel_params_buf32[22] = 0; // digests_offset
	md5_controller->kernel_params_buf64[23] = 0; // gid_max

	md5_controller->kernel_params[0] = &md5_controller->d_pws_amp_buf;
	md5_controller->kernel_params[1] = &md5_controller->d_tmps;
	md5_controller->kernel_params[2] = &md5_controller->d_bitmap_s1_a;
	md5_controller->kernel_params[3] = &md5_controller->d_bitmap_s1_b;
	md5_controller->kernel_params[4] = &md5_controller->d_bitmap_s1_c;
	md5_controller->kernel_params[5] = &md5_controller->d_bitmap_s1_d;
	md5_controller->kernel_params[6] = &md5_controller->d_bitmap_s2_a;
	md5_controller->kernel_params[7] = &md5_controller->d_bitmap_s2_b;
	md5_controller->kernel_params[8] = &md5_controller->d_bitmap_s2_c;
	md5_controller->kernel_params[9] = &md5_controller->d_bitmap_s2_d;
	md5_controller->kernel_params[10] = &md5_controller->d_plain_bufs;
	md5_controller->kernel_params[11] = &md5_controller->d_digests_buf;
	md5_controller->kernel_params[12] = &md5_controller->d_hashes_shown;
	md5_controller->kernel_params[13] = &md5_controller->d_salt_bufs;
	md5_controller->kernel_params[14] = &md5_controller->d_return_buf;
	md5_controller->kernel_params[15] = &md5_controller->kernel_params_buf32[15];
	md5_controller->kernel_params[16] = &md5_controller->kernel_params_buf32[16];
	md5_controller->kernel_params[17] = &md5_controller->kernel_params_buf32[17];
	md5_controller->kernel_params[18] = &md5_controller->kernel_params_buf32[18];
	md5_controller->kernel_params[19] = &md5_controller->kernel_params_buf32[19];
	md5_controller->kernel_params[20] = &md5_controller->kernel_params_buf32[20];
	md5_controller->kernel_params[21] = &md5_controller->kernel_params_buf32[21];
	md5_controller->kernel_params[22] = &md5_controller->kernel_params_buf32[22];
	md5_controller->kernel_params[23] = &md5_controller->kernel_params_buf64[23];

}

int set_kernel_args(hc_md5_device_param_t* md5_controller, cl_kernel* kernel) {
	cl_int ret;
	for (u32 i = 0; i <= 14; i++)
	{
		ret = clSetKernelArg( *kernel, i, sizeof(cl_mem), md5_controller->kernel_params[i]);

		if (ret == -1) return -1;
	}

	for (u32 i = 15; i <= 22; i++)
	{
		ret = clSetKernelArg( *kernel, i, sizeof(cl_uint), md5_controller->kernel_params[i]);

		if (ret == -1) return -1;
	}

	for (u32 i = 23; i <= 23; i++)
	{
		ret = clSetKernelArg(*kernel, i, sizeof(cl_ulong), md5_controller->kernel_params[i]);

		if (ret == -1) return -1;
	}
	return 0;
}

void create_kernels(hc_md5_device_param_t* md5_controller) {
	cl_int ret = 0;

	// Create the OpenCL kernel
	md5_controller->kernel1 = clCreateKernel(md5_controller->program, "m00500_init", &ret);
	printf("ret at %d is %s\n", __LINE__, getErrorString(ret));
	ret = get_kernel_threads(md5_controller, md5_controller->kernel1, &md5_controller->kernel_threads_by_wgs_kernel1);

	md5_controller->kernel2 = clCreateKernel(md5_controller->program, "m00500_loop", &ret);
	printf("ret at %d is %s\n", __LINE__, getErrorString(ret));
	ret = get_kernel_threads(md5_controller, md5_controller->kernel2, &md5_controller->kernel_threads_by_wgs_kernel2);

	md5_controller->kernel3 = clCreateKernel(md5_controller->program, "m00500_comp", &ret);
	printf("ret at %d is %s\n", __LINE__, getErrorString(ret));
	ret = get_kernel_threads(md5_controller, md5_controller->kernel3, &md5_controller->kernel_threads_by_wgs_kernel3);
}

void run_kernel(hc_md5_device_param_t* md5_controller, const u32 kern_run, const u64 num) {
	u64 num_elements = num;
	cl_kernel kernel = NULL;
	u64 kernel_threads = 0;
	cl_event event;

	md5_controller->kernel_params_buf64[23] = num; // gid_max

	switch (kern_run) {
	case 1:
		kernel = md5_controller->kernel1;
		kernel_threads = md5_controller->kernel_threads_by_wgs_kernel1;
		break;
	case 2:
		kernel = md5_controller->kernel2;
		kernel_threads = md5_controller->kernel_threads_by_wgs_kernel2;
		break;
	case 3:
		kernel = md5_controller->kernel3;
		kernel_threads = md5_controller->kernel_threads_by_wgs_kernel3;
		break;
	}

	while (num_elements % kernel_threads) num_elements++;

	// Set the arguments of the kernel
	cl_int ret = set_kernel_args(md5_controller, &(kernel));
	if(ret != 0) printf("ret at %d is %s for kernel%d\n", __LINE__, getErrorString(ret), (int)kern_run);

	const size_t global_work_size[3] = { num_elements,   1, 1 };
	const size_t local_work_size[3] = { kernel_threads, 1, 1 };

	ret = clEnqueueNDRangeKernel(md5_controller->command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, &event);
	if (ret != 0) printf("ret at %d is %s for kernel%d\n", __LINE__, getErrorString(ret), (int)kern_run);

	ret = clFlush(md5_controller->command_queue);
	if (ret != 0) printf("ret at %d is %s for kernel%d\n", __LINE__, getErrorString(ret), (int)kern_run);

	ret = clWaitForEvents(1, &event);
	if (ret != 0) printf("ret at %d is %s for kernel%d\n", __LINE__, getErrorString(ret), (int)kern_run);

	cl_ulong time_start;
	cl_ulong time_end;

	ret = clGetEventProfilingInfo(event, CL_PROFILING_COMMAND_START, sizeof(time_start), &time_start, NULL);// if (ret == -1) return -1;
	//if (ret != 0) printf("ret at %d is %s for kernel%d\n", __LINE__, getErrorString(ret), (int)kern_run);

	ret = clGetEventProfilingInfo(event, CL_PROFILING_COMMAND_END, sizeof(time_end), &time_end, NULL);// if (ret == -1) return -1;
	//if (ret != 0) printf("ret at %d is %s for kernel%d\n", __LINE__, getErrorString(ret), (int)kern_run);

	const double exec_us = (double)(time_end - time_start) / 1000;

	clReleaseEvent(event);
	//if (ret != 0) printf("ret at %d is %s for kernel%d\n", __LINE__, getErrorString(ret), (int)kern_run);
	clFinish(md5_controller->command_queue);
	//if (ret != 0) printf("ret at %d is %s for kernel%d\n", __LINE__, getErrorString(ret), (int)kern_run);
}

void execute(hc_md5_device_param_t* md5_controller, hashes_t* md5_hashes) {
	//I think this only works for 1 right now
	cl_int ret = 0;
	pw_t pw; memset(&pw, 0, sizeof(pw));

	char *pw_ptr = (char *)&pw.i;

	int pw_len = (int)strlen("$1$38652870$DUjsu4TTlTsOe/xxZ05uf/");

	memcpy(pw_ptr, "$1$38652870$DUjsu4TTlTsOe/xxZ05uf/", pw_len);

	pw.pw_len = pw_len;

	ret = clEnqueueWriteBuffer(md5_controller->command_queue, md5_controller->d_pws_buf, CL_TRUE, 0, 1 * sizeof(pw_t), &pw, 0, NULL, NULL);

	run_kernel(md5_controller, 1, 1);

	u32 salt_pos = 0;
	salt_t* salt_buf = &md5_hashes->salts_buf[salt_pos];
	u32 iter = salt_buf->salt_iter;
	//iter = 5;
	const u32 loop_step = 1;

	for (u32 loop_pos = 0; loop_pos < iter; loop_pos += loop_step) {
		u32 loop_left = iter - loop_pos;
		md5_controller->kernel_params_buf32[28] = loop_pos;
		md5_controller->kernel_params_buf32[29] = loop_left;
		run_kernel(md5_controller, 2, 1);
	}

	run_kernel(md5_controller, 3, 1);

	u32 num_cracked = 0;

	ret = clEnqueueReadBuffer(md5_controller->command_queue, md5_controller->d_return_buf, CL_TRUE, 0, sizeof(u32), &num_cracked, 0, NULL, NULL);
	if (ret != 0) printf("ret at %d is %s\n", __LINE__, getErrorString(ret));

	if (num_cracked) {
		printf("fuck yeah, cracked it");
		plain_t* cracked = (plain_t*) calloc(num_cracked, sizeof(plain_t));
		ret = clEnqueueReadBuffer(md5_controller->command_queue, md5_controller->d_plain_bufs, CL_TRUE, 0, num_cracked * sizeof(plain_t), cracked, 0, NULL, NULL);
		u32 cpt_cracked = 0;

		for (u32 i = 0; i < num_cracked; i++)
		{
			const u32 hash_pos = cracked[i].hash_pos;

			if (md5_hashes->digests_shown[hash_pos] == 1) continue;

			md5_hashes->digests_shown[hash_pos] = 1;

			md5_hashes->digests_done++;

			cpt_cracked++;

			salt_buf->digests_done++;

			if (salt_buf->digests_done == salt_buf->digests_cnt){
				md5_hashes->salts_shown[salt_pos] = 1;

				md5_hashes->salts_done++;
			}
			//check_hash( device_param, &cracked[i]);
		}
		free(cracked);
	}
}

int runMD5(void) {
	printf("started running\n");
	cl_int ret = 0;
	bool cleanup = true; //should alwas be true

	//print_clinfo();
	//return 0;

	hashconfig_t* md5_hashconfig = (hashconfig_t *) calloc(1, sizeof(hashconfig_t));
	hc_md5_device_param_t* md5_controller = (hc_md5_device_param_t *)calloc(1, sizeof(hc_md5_device_param_t));
	bitmap_ctx_t* bitmap = (bitmap_ctx_t*)calloc(1, sizeof(bitmap_ctx_t));
	hashes_t* md5_hashes = (hashes_t*)calloc(1, sizeof(hashes_t));

	load_md5_hashconfig(md5_hashconfig);
	setup_hashes(md5_hashconfig, md5_hashes);
	bitmap_ctx_init(bitmap, md5_hashconfig, md5_hashes);
	setup_device(md5_controller);
	set_controller_sizes(md5_controller, md5_hashconfig, md5_hashes);

	// Load the kernel source code into the array source_str
	build_program(md5_controller, "md5_crypt.cl");

	createBuffers(md5_controller, bitmap, md5_hashes);

	load_controller_arg_array(md5_controller, bitmap);
	create_kernels(md5_controller);	

	printf("before execution\n");
	// Execute the OpenCL kernel on the list
	//size_t global_item_size = LIST_SIZE; // Process the entire lists
	//size_t local_item_size = 64; // Divide work items into groups of 64
	//ret = clEnqueueNDRangeKernel(md5_controller->command_queue, kernel, 1, NULL,
	execute(md5_controller, md5_hashes);
	//	&global_item_size, &local_item_size, 0, NULL, NULL);
	printf("after execution\n");
	// Read the memory buffer C on the device to the local variable C
	//ret = clEnqueueReadBuffer(md5_controller->command_queue, c_mem_obj, CL_TRUE, 0,
	//	LIST_SIZE * sizeof(int), C, 0, NULL, NULL);
	printf("after copying\n");
	// Display the result to the screen

	if (cleanup = true) {
		// Clean up
		ret = clFlush(md5_controller->command_queue);
		ret = clFinish(md5_controller->command_queue);
		if (md5_controller->d_pws_buf)        clReleaseMemObject(md5_controller->d_pws_buf);
		if (md5_controller->d_pws_amp_buf)    clReleaseMemObject(md5_controller->d_pws_amp_buf);
		if (md5_controller->d_bitmap_s1_a)    clReleaseMemObject(md5_controller->d_bitmap_s1_a);
		if (md5_controller->d_bitmap_s1_b)    clReleaseMemObject(md5_controller->d_bitmap_s1_b);
		if (md5_controller->d_bitmap_s1_c)    clReleaseMemObject(md5_controller->d_bitmap_s1_c);
		if (md5_controller->d_bitmap_s1_d)    clReleaseMemObject(md5_controller->d_bitmap_s1_d);
		if (md5_controller->d_bitmap_s2_a)    clReleaseMemObject(md5_controller->d_bitmap_s2_a);
		if (md5_controller->d_bitmap_s2_b)    clReleaseMemObject(md5_controller->d_bitmap_s2_b);
		if (md5_controller->d_bitmap_s2_c)    clReleaseMemObject(md5_controller->d_bitmap_s2_c);
		if (md5_controller->d_bitmap_s2_d)    clReleaseMemObject(md5_controller->d_bitmap_s2_d);
		if (md5_controller->d_plain_bufs)     clReleaseMemObject(md5_controller->d_plain_bufs);
		if (md5_controller->d_digests_buf)    clReleaseMemObject(md5_controller->d_digests_buf);
		if (md5_controller->d_hashes_shown)   clReleaseMemObject(md5_controller->d_hashes_shown);
		if (md5_controller->d_salt_bufs)      clReleaseMemObject(md5_controller->d_salt_bufs);
		if (md5_controller->d_tmps)           clReleaseMemObject(md5_controller->d_tmps);
		if (md5_controller->d_return_buf)     clReleaseMemObject(md5_controller->d_return_buf);

		if (md5_controller->kernel1)          clReleaseKernel(md5_controller->kernel1);
		if (md5_controller->kernel2)          clReleaseKernel(md5_controller->kernel2);
		if (md5_controller->kernel3)          clReleaseKernel(md5_controller->kernel3);


		if (md5_controller->program)          clReleaseProgram(md5_controller->program);
		if (md5_controller->command_queue)    clReleaseCommandQueue(md5_controller->command_queue);
		if (md5_controller->context)          clReleaseContext(md5_controller->context);

		md5_controller->pws_buf = NULL;
		md5_controller->combs_buf = NULL;
		md5_controller->hooks_buf = NULL;

		md5_controller->d_pws_buf = NULL;
		md5_controller->d_pws_amp_buf = NULL;
		md5_controller->d_bitmap_s1_a = NULL;
		md5_controller->d_bitmap_s1_b = NULL;
		md5_controller->d_bitmap_s1_c = NULL;
		md5_controller->d_bitmap_s1_d = NULL;
		md5_controller->d_bitmap_s2_a = NULL;
		md5_controller->d_bitmap_s2_b = NULL;
		md5_controller->d_bitmap_s2_c = NULL;
		md5_controller->d_bitmap_s2_d = NULL;
		md5_controller->d_plain_bufs = NULL;
		md5_controller->d_digests_buf = NULL;
		md5_controller->d_hashes_shown = NULL;
		md5_controller->d_salt_bufs = NULL;
		md5_controller->d_tmps = NULL;
		md5_controller->d_return_buf = NULL;
		md5_controller->kernel1 = NULL;
		md5_controller->kernel2 = NULL;
		md5_controller->kernel3 = NULL;
		md5_controller->program = NULL;
		md5_controller->command_queue = NULL;
		md5_controller->context = NULL;

		free(md5_hashes->hashes_buf->digest);
		free(md5_hashes->hashes_buf->salt);
		free(md5_hashes->hashes_buf);
		free(md5_hashes);
		free(bitmap);
		free(md5_controller->platforms);
		free(md5_hashconfig);
		free(md5_controller);
		return 0;
	}
	return 0;
}

int runTest(void){
	printf("started running\n");

	// Create the two input vectors
	int i;
	const int LIST_SIZE = 1024;
	int *A = (int*)malloc(sizeof(int)*LIST_SIZE);
	int *B = (int*)malloc(sizeof(int)*LIST_SIZE);
	for (i = 0; i < LIST_SIZE; i++) {
		A[i] = i;
		B[i] = LIST_SIZE - i;
	}

	// Load the kernel source code into the array source_str
	FILE *fp;
	char *source_str;
	size_t source_size;

	//fp = fopen("kernel.cl", "r");
	fopen_s(&fp, "kernel.cl", "r");
	if (!fp) {
		fprintf(stderr, "Failed to load kernel.\n");
		exit(1);
	}
	source_str = (char*)malloc(MAX_SOURCE_SIZE);
	source_size = fread(source_str, 1, MAX_SOURCE_SIZE, fp);
	fclose(fp);
	printf("kernel loading done\n");
	// Get platform and device information
	cl_device_id device_id = NULL;
	cl_uint ret_num_devices;
	cl_uint ret_num_platforms;


	cl_int ret = clGetPlatformIDs(0, NULL, &ret_num_platforms);
	cl_platform_id *platforms = NULL;
	platforms = (cl_platform_id*)malloc(ret_num_platforms * sizeof(cl_platform_id));

	ret = clGetPlatformIDs(ret_num_platforms, platforms, NULL);
 printf("ret at %d is %s\n", __LINE__, getErrorString(ret));

	ret = clGetDeviceIDs(platforms[1], CL_DEVICE_TYPE_ALL, 1,
		&device_id, &ret_num_devices);
 printf("ret at %d is %s\n", __LINE__, getErrorString(ret));
	// Create an OpenCL context
	cl_context context = clCreateContext(NULL, 1, &device_id, NULL, NULL, &ret);
 printf("ret at %d is %s\n", __LINE__, getErrorString(ret));

	// Create a command queue
	cl_command_queue command_queue = clCreateCommandQueue(context, device_id, 0, &ret);
 printf("ret at %d is %s\n", __LINE__, getErrorString(ret));

	// Create memory buffers on the device for each vector 
	cl_mem a_mem_obj = clCreateBuffer(context, CL_MEM_READ_ONLY,
		LIST_SIZE * sizeof(int), NULL, &ret);
	cl_mem b_mem_obj = clCreateBuffer(context, CL_MEM_READ_ONLY,
		LIST_SIZE * sizeof(int), NULL, &ret);
	cl_mem c_mem_obj = clCreateBuffer(context, CL_MEM_WRITE_ONLY,
		LIST_SIZE * sizeof(int), NULL, &ret);

	// Copy the lists A and B to their respective memory buffers
	ret = clEnqueueWriteBuffer(command_queue, a_mem_obj, CL_TRUE, 0,
		LIST_SIZE * sizeof(int), A, 0, NULL, NULL);
 printf("ret at %d is %s\n", __LINE__, getErrorString(ret));

	ret = clEnqueueWriteBuffer(command_queue, b_mem_obj, CL_TRUE, 0,
		LIST_SIZE * sizeof(int), B, 0, NULL, NULL);
 printf("ret at %d is %s\n", __LINE__, getErrorString(ret));

	printf("before building\n");
	// Create a program from the kernel source
	cl_program program = clCreateProgramWithSource(context, 1,
		(const char **)&source_str, (const size_t *)&source_size, &ret);
 printf("ret at %d is %s\n", __LINE__, getErrorString(ret));

	// Build the program
	ret = clBuildProgram(program, 1, &device_id, NULL, NULL, NULL);
 printf("ret at %d is %s\n", __LINE__, getErrorString(ret));

	printf("after building\n");
	// Create the OpenCL kernel
	cl_kernel kernel = clCreateKernel(program, "vector_add", &ret);
 printf("ret at %d is %s\n", __LINE__, getErrorString(ret));

	// Set the arguments of the kernel
	ret = clSetKernelArg(kernel, 0, sizeof(cl_mem), (void *)&a_mem_obj);
 printf("ret at %d is %s\n", __LINE__, getErrorString(ret));

	ret = clSetKernelArg(kernel, 1, sizeof(cl_mem), (void *)&b_mem_obj);
 printf("ret at %d is %s\n", __LINE__, getErrorString(ret));

	ret = clSetKernelArg(kernel, 2, sizeof(cl_mem), (void *)&c_mem_obj);
 printf("ret at %d is %s\n", __LINE__, getErrorString(ret));

	//added this to fix garbage output problem
	//ret = clSetKernelArg(kernel, 3, sizeof(int), &LIST_SIZE);

	printf("before execution\n");
	// Execute the OpenCL kernel on the list
	size_t global_item_size = LIST_SIZE; // Process the entire lists
	size_t local_item_size = 64; // Divide work items into groups of 64
	ret = clEnqueueNDRangeKernel(command_queue, kernel, 1, NULL,
		&global_item_size, &local_item_size, 0, NULL, NULL);
	printf("after execution\n");
	// Read the memory buffer C on the device to the local variable C
	int *C = (int*)malloc(sizeof(int)*LIST_SIZE);
	ret = clEnqueueReadBuffer(command_queue, c_mem_obj, CL_TRUE, 0,
		LIST_SIZE * sizeof(int), C, 0, NULL, NULL);
	printf("after copying\n");
	// Display the result to the screen
	for (i = 0; i < LIST_SIZE; i++)
		printf("%d + %d = %d\n", A[i], B[i], C[i]);

	// Clean up
	ret = clFlush(command_queue);
	ret = clFinish(command_queue);
	ret = clReleaseKernel(kernel);
	ret = clReleaseProgram(program);
	ret = clReleaseMemObject(a_mem_obj);
	ret = clReleaseMemObject(b_mem_obj);
	ret = clReleaseMemObject(c_mem_obj);
	ret = clReleaseCommandQueue(command_queue);
	ret = clReleaseContext(context);
	free(A);
	free(B);
	free(C);
	return 0;
}

int main(void) {
	return runMD5();
}