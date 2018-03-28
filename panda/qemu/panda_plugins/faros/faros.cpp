/*
 *NOTES:
 *    Physical Write Callbacks seems to fire on qemu_st instructions and not
 *    on the normal st instructions. Writes seem to fire on qemu_ld's not ld's.
 *
 *    Regular ld/st ops are reads/writes to memory/registers on the HOST
 *    while qemu_ld/qemu_st are reads/writes to the GUEST memory.
 *
 *
 *    Looks like PANDA doesn't provide a nice way of instrumenting based on
 *    the TCG code that will be run. Instead you have to choose to intrument
 *    based on the guest machine code to be run. This means we'll need to
 *    handle different ARCHs differently. Not ideal but if that's all we've got...
 *
 */
/*
 * TO-DO List:
 *
 * TODO Properly handle branches, both cond and uncond.
 * TODO Convert shadow memory to use more efficient data structure
 * TODO ifdef guard portions that are arch specific
 *
 */

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <cstdio>
#include <unordered_map>
#include <map>
#include <unordered_set>
#include <vector>
#include <set>
#include <queue>
#include <list>
#include <deque>
#include <algorithm>

#include <thread>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

extern "C" {
#include "tcg.h"
#include "config.h"
#include "monitor.h"
#include "qemu-common.h"
#include "panda_common.h"
#include "panda_plugin.h"

//win7proc
#include "rr_log.h"
#include "pandalog.h"        
#include "cpu.h"

#include "../osi/osi_proc_events.h"
#include "../osi/os_intro.h"
#include "../syscalls2/syscalls2.h"

#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"

#include "../syscalls2/gen_syscalls_ext_typedefs.h"
#include "../syscalls2/syscalls_common.h"
#include "panda_plugin_plugin.h"

#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>

#include <sys/time.h>

bool init_plugin(void *);
void uninit_plugin(void *);

#ifndef CONFIG_SOFTMMU
#include "linux-user/syscall_defs.h"
#endif
}

#define CCS_ENABLED 1 // Uncomment this to enable detection for in-memory injection attack detection
//#define OUTPUT_SMEM 1 // Uncomment this to create an .smem output for whole memory

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
    bool init_plugin(void *);
    void uninit_plugin(void *);
    int monitor_callback(Monitor *, const char *);
    int before_block_exec(CPUState *, TranslationBlock *);
    int after_block_exec(CPUState *env, TranslationBlock *tb,
                         TranslationBlock *next_tb);
    int phys_read_callback(CPUState *env, target_ulong pc, target_ulong addr,
                           target_ulong size, void *buf);
    int phys_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                            target_ulong size, void *buf);
    int faros_net_recv(CPUState *env, uint64_t dst_addr, uint32_t num_bytes);

}

#ifdef TARGET_I386

/***** THIS PART DEFINES THE REQUIRED DATA STUCTURES *****/

#define BASIC_TAINT 1 // TODO: change it to enum
#define FULL_TAINT  2
#define MAX_PID_LIST_LEN 10
#define MAX_PNAMES_LIST_LEN 100
#define MAX_SYSCALL_NO 1000000

#define MAX_PROV_LIST 12


// a list of pids
typedef struct pid_list{
    uint32_t   pid[MAX_PID_LIST_LEN];
    uint32_t   count;
}pid_list;

typedef struct pname_list{
    std::string   pname[MAX_PNAMES_LIST_LEN];
    uint32_t      count;
}pname_list;

typedef struct file_object{ // File object according to CDM 13
    char *filename;         // NULL terminated string containing the file name
    uint32_t version;       // number of times a file has been accessed so far
}FileObject;


typedef struct netflow_object{ // Netflow object according to CDM 13
    char     *src_ip;    // NULL terminated string containing the source ip address
    uint32_t src_port;
    char     *des_ip;    // NULL terminated string containing the destination ip address
    uint32_t des_port;
    uint32_t proto;
}NetflowObject;

typedef uint8_t misc_t;
typedef target_ulong cr3_t;
typedef NetflowObject net_flow_t;//*NetflowObjectP;
typedef FileObject file_obj_t;//*FileObjectP;

typedef struct process_info {
	target_ulong		pid;
	target_ulong		ppid;	
	//int		        tid;
	std::string		    process_name;
}process_info;

typedef struct syscall_argument {
	void *		    arg1;
	uint32_t	    size1;
	void *		    arg2;
	uint32_t	    size2;
	target_ulong	address;
	uint32_t 	    pointer_value1;
	uint32_t 	    pointer_value2;
	uint32_t 	    pointer_size1;
	uint32_t 	    pointer_size2;
	bool            string_flag;
	bool            pointer_flag;
}syscall_argument;

typedef struct syscall_info {
	target_ulong		    syscall_no;
	struct syscall_argument	args[SYSCALL_ARG_MAX];
	uint32_t		        args_number;
	target_ulong		    retval;
	cr3_t		            cr3;
	long long       	    timestamp;
	file_obj_t              *fo = NULL;
}syscall_info;


// one-byte tag
typedef enum misc_tag{
    INCOMING_FLOW_TAG = 1,
    OUTGOING_FLOW_TAG = 2,
    EXPORT_TABLE_TAG = 3
}MiscTag;

typedef enum tag_type{
    CR3 = 1,
    NET_FLOW = 2,
    FILE_OBJ = 3,
    MISC = 4
}TagType;

typedef uint32_t taint_key_t;
typedef struct taint_data{
    taint_key_t tag_index;
    TagType     tag_type;
}TaintData;

typedef TaintData taint_data_t;//TaintDataP;


// FAROS plugin input arguments
pid_list pids;                // List of pids specified by user that we should filter the outputs for them
pname_list pnames;            // List of process names specified by user that we should filter the outputs for them
bool     taint_enabled;       // on/off
uint32_t taint_level;         // basic/full
bool     rolling;             // on/off, enales/disable rolling output files
uint32_t rolling_time;        // Rolling period time in seconds
bool     faros_enabled;       // whether FAROS start working at srartup or not

//bool taint_in_kernel_enabled = true;

// Output files
std::ofstream faros_log;
std::ofstream faros_trace;
std::ofstream faros_cr3;
std::ofstream faros_string;
std::ofstream faros_file;
std::ofstream faros_netflow;
#ifdef OUTPUT_SMEM
std::ofstream faros_smem;
#endif
#ifdef CCS_ENABLED
std::ofstream faros_potential_injection;
#endif
// A thread for rolling
pthread_t write_thread;
pthread_mutex_t thread_lock;

long int file_count = 0;
long int netflow_count = 0;
long int syscalls_info_count = 0;
syscall_info *syscalls_info; // it holds the whole system calls info, e.g name, arguments, etc
std::unordered_map<target_ulong, process_info> cr3_to_processinfo; // it maps cr3 value to a process
std::unordered_map<target_ulong, std::list<taint_data_t>> smem; // it keeps provenance info
std::unordered_map<target_ulong, std::queue<target_ulong>> reads; // it keeps memory reads
std::unordered_map<target_ulong, std::queue<target_ulong>> writes; // it keeps memory writes
std::unordered_map<std::string, uint32_t> file_access; // it keeps the number of times a file has been accessed
std::unordered_map<std::string, target_ulong> final_files; // it keeps a unique list of file objects
std::unordered_map<std::string, target_ulong> final_netflows; // it keeps a unique list of netFlow objects

std::unordered_map<target_ulong, std::list<taint_data_t>> sreg;
typedef std::unordered_map<target_ulong, std::list<taint_data_t>> shadow_t;


std::unordered_map<taint_key_t, cr3_t> cr3_dic; // it keeps a unique list of cr3
std::unordered_map<taint_key_t, file_obj_t> fileobj_dic; // it keeps a unique list of file objects
std::unordered_map<taint_key_t, net_flow_t> netflow_dic; // it keeps a unique list of netflow objects
taint_key_t cr3_number = 0;
taint_key_t netflow_number = 0;
taint_key_t fileobj_number = 0;


bool tag_kernel = true; // it should be true for potential in-memory injection attack detection
/***** THIS PART HANDLES IN-MEMORY INJECTIUON ATTACK DETECTION *****/
#ifdef CCS_ENABLED
std::unordered_map<target_ulong, std::list<taint_data_t>> potential_injection_smem; // it keeps provenance info


bool check_for_potential_injection_attack(CPUState *env, target_ulong addr, target_ulong pc, target_ulong size){

    // Property #1: check if it's reading the export table 
    bool export_table = false;  
    for (int i=0; i < 4; i++){
        for(auto td: smem[addr+i]){
            if(td.tag_type == MISC){
                if(td.tag_index == EXPORT_TABLE_TAG){ // it has an export table record
                    export_table = true;
                    break;
                }
            }
        }
    }
    if (!export_table)
        return false;

    //faros_log << "\nfound export_table";faros_log.flush();
    //target_ulong pc = env->eip;//panda_guest_pc;//+ base_address - 1;

    // Property #2: check if the prov list has at least two processes 
    int proc_count = 0;
    pc = panda_virt_to_phys(env, pc);
    for (target_ulong i = 0; i < size; i++){
        proc_count = 0;
        for(auto td: smem[pc + i]){
        
           switch(td.tag_type){
                case MISC:
                    break;
                case CR3:
                    proc_count += 1;
                    break;
                default:
                    break;
            }
         }
    }

    if (proc_count < 2)
        return false;
    
    if (pc == 4294967295 || pc == 0 || pc == 1 || pc == 2)
        return false;

    //faros_log << "\nfound potential in-memory injection attack...";faros_log.flush();

    if(potential_injection_smem[pc].empty())
        potential_injection_smem[pc] = smem[pc];
    return true;    

}


void write_potential_injection(){

    if(potential_injection_smem.size() > 1){
         faros_potential_injection << "\n >> Found potential in-memory injection attack!";
         faros_potential_injection << "\n >> See below for details:\n";
         faros_potential_injection << "\n<<memory>> \t\t\t\t <<provenance list>>\n";
         faros_potential_injection << "========== \t ==============================================================================================================";
    }
    for (auto i: potential_injection_smem ){
    
        std::stringstream sstream;
        sstream << std::hex << i.first;
        //std::string result = sstream.str();

        faros_potential_injection << "\n0x" << sstream.str() << " -> ";
        for (auto td:i.second){
            switch(td.tag_type){
                case CR3:{
                    cr3_t cr3 = cr3_dic[td.tag_index];    
                    if (cr3 == 1)
                        faros_log << "kread;";
                    else if (cr3  == 2)
                        faros_log << "kwrite;";
                    else if (cr3_to_processinfo.count(cr3) !=0)
                        faros_potential_injection << cr3_to_processinfo[cr3].process_name << ";";
                    else
                        faros_potential_injection << "unknown:" << cr3 << ";";
                    }
                    break;
                case NET_FLOW:{
                    net_flow_t nfo = netflow_dic[td.tag_index];
                    faros_potential_injection << "(" << nfo.src_ip << ":" << nfo.src_port << "," << nfo.des_ip << ":" << nfo.des_port << ");";
                    }
                    break;
                case FILE_OBJ:{
                    file_obj_t fo = fileobj_dic[td.tag_index];
                    faros_potential_injection << fo.filename << ":" << fo.version << ";";
                    }
                    break;
                case MISC:{
                    misc_t misc = td.tag_index;
                    if (misc == OUTGOING_FLOW_TAG)
                        faros_potential_injection << "OUTGOING_FLOW" << ";";
                    if (misc == INCOMING_FLOW_TAG)
                        faros_potential_injection << "INCOMING_FLOW" << ";";
                    if (misc == EXPORT_TABLE_TAG)
                        faros_potential_injection << "EXPORT_TABLE;";
                    }
                    break;
                 default:
                    break;
            }
            faros_potential_injection.flush();
        }
    }
}


#endif

/***** THIS PART HANDLES TAINTING MEMORY WITH DIFFERENT OBJECTS *****/

/****************** CR3 TAINTIG ******************/

// since the maximum number of unique proccess is very low, the search here will be O(1)
// returns the index if already exists, if it does not exist it adds the new cr3

taint_key_t get_tag_index_cr3(cr3_t cr3){
     for(auto i: cr3_dic){
         if(i.second == cr3)
             return i.first;
     }
     cr3_dic[cr3_number++] = cr3;
     return cr3_number - 1;
}

inline void add_taint_cr3(shadow_t &shadow, target_ulong addr, taint_key_t index){
    
    if(shadow[addr].size() >= MAX_PROV_LIST) // prevent the provenance list to explode
        return;

    taint_data_t new_taint;
    new_taint.tag_index = index;
    new_taint.tag_type = CR3;
    shadow[addr].push_front(new_taint);
}

inline uint32_t taint_shadow_cr32(shadow_t &shadow, CPUState *env, target_ulong addr, taint_key_t index){
	if (shadow[addr].empty())
	    add_taint_cr3(shadow, addr, index);
	else {
	    bool already_exist = false;
	    for (auto i: shadow[addr])
	         if(i.tag_type == CR3 && i.tag_index == index){
			     already_exist = true;
			     break;
		     }
	    if(!already_exist)
	        add_taint_cr3(shadow, addr, index); 
	    else
	        return 0;  
	}
	return 1;
}
	
// taint memory address, addr, with cr3 value
inline uint32_t taint_shadow_cr3(shadow_t &shadow, CPUState *env, target_ulong addr, cr3_t cr3) {

    taint_key_t index = get_tag_index_cr3(cr3);
    return taint_shadow_cr32(shadow, env, addr, index);

}
/****************** Netflow TAINTIG ******************/

// since the maximum number of unique netflow records is very low, the search here will be O(1)
// returns the index if already exists, if it does not exist it adds the new netflow
taint_key_t get_tag_index_netflow(net_flow_t nfo){
     for(auto i: netflow_dic){
         if(!strcmp(i.second.src_ip, nfo.src_ip) && !strcmp(i.second.des_ip, nfo.des_ip) \
            && i.second.src_port == nfo.src_port && i.second.des_port == nfo.des_port)
             return i.first;
     }
     netflow_dic[netflow_number++] = nfo;
     faros_log << "\n netflow:" << netflow_dic[netflow_number-1].src_ip << ":" << netflow_dic[netflow_number-1].des_ip;faros_log.flush();
     return netflow_number - 1;
}
		
// caller must allocate the memory for nfo
inline void add_taint_netflow(shadow_t &shadow, target_ulong addr, taint_key_t index){

    if(shadow[addr].size() >= MAX_PROV_LIST) // prevent the provenance list to explode
        return;
    taint_data_t new_taint;
    new_taint.tag_index = index;
    new_taint.tag_type = NET_FLOW;
    shadow[addr].push_front(new_taint);
}


inline uint32_t taint_shadow_netflow2(shadow_t &shadow, CPUState *env, target_ulong addr, taint_key_t index){

	if (shadow[addr].empty())
	    add_taint_netflow(shadow, addr, index);
	else {
	    bool already_exist = false;
	    for (auto i: shadow[addr])
	         if(i.tag_type == NET_FLOW && i.tag_index == index){
			     already_exist = true;
			     break;
		     }	
	    if(!already_exist)
	        add_taint_netflow(shadow, addr, index);
	    else
	       return 0;
	}
	return 1;
}


// taint memory address, addr, with netflow object, nfo
inline uint32_t taint_shadow_netflow(shadow_t &shadow, CPUState *env, target_ulong addr, net_flow_t nfo){

    taint_key_t index = get_tag_index_netflow(nfo);
    return taint_shadow_netflow2(shadow, env, addr, index);

}

/****************** FileObject TAINTIG ******************/

// since the maximum number of unique fileobj records is very low, the search here will be O(1)
// returns the index if already exists, if it does not exist it adds the new file object
taint_key_t get_tag_index_fileobj(file_obj_t fo){
     for (auto i: fileobj_dic){
         if (!strcmp(i.second.filename, fo.filename) && i.second.version == fo.version)
             return i.first;
     }
     fileobj_dic[fileobj_number++] = fo; // TODO
     return fileobj_number - 1;
}
		
// caller must allocate the memory for fo
inline void add_taint_fileobj(shadow_t &shadow, target_ulong addr, taint_key_t index){

    if(shadow[addr].size() >= MAX_PROV_LIST) // prevent the provenance list to explode
        return;
    taint_data_t new_taint;
    new_taint.tag_index = index;
    new_taint.tag_type = FILE_OBJ;
    shadow[addr].push_front(new_taint);
}


inline uint32_t taint_shadow_fileobj2(shadow_t &shadow, CPUState *env, target_ulong addr, taint_key_t index){
	
	if (shadow[addr].empty())
	    add_taint_fileobj(shadow, addr, index);
	else {
	    bool already_exist = false;
	    for (auto i: shadow[addr])
	         if(i.tag_type == FILE_OBJ && i.tag_index == index){
			     already_exist = true;
			     break;
		     }
	    if(!already_exist)
	        add_taint_fileobj(shadow, addr, index);
	    else
	        return 0;
	}
	return 1;
}

// taint memory address, addr, with file object, fo
// returns 0, if the record is already existed
inline uint32_t taint_shadow_fileobj(shadow_t &shadow, CPUState *env, target_ulong addr, file_obj_t fo){

    taint_key_t index = get_tag_index_fileobj(fo);
    return taint_shadow_fileobj2(shadow, env, addr, index);
}

/****************** MISC TAINTIG ******************/

inline void add_taint_misc(shadow_t &shadow, target_ulong addr, taint_key_t netsource){
    
    if(shadow[addr].size() >= MAX_PROV_LIST) // prevent the provenance list to explode
        return;
    taint_data_t new_taint;
    new_taint.tag_index = netsource;
    new_taint.tag_type = MISC;
    shadow[addr].push_front(new_taint);
}

// taint memory address, addr, with cr3 value, cr3
inline void taint_shadow_misc(shadow_t &shadow, CPUState *env, target_ulong addr, misc_t netsource) {
        
	if (shadow[addr].empty())
	    add_taint_misc(shadow, addr, (taint_key_t)netsource);
	else {
	    bool already_exist = false;
	    for (auto i: shadow[addr])
            if(i.tag_type == MISC && i.tag_index == netsource){
             already_exist = true;
             break;
            }
	    if(!already_exist)
	        add_taint_misc(shadow, addr, (taint_key_t)netsource);
	}

}

/****************** MAIN TAINT FUNCTION ******************/
inline void taint_shadow(shadow_t &shadow, CPUState *env, target_ulong addr, taint_data_t td) {

    switch(td.tag_type){
        case CR3:
            taint_shadow_cr32(shadow, env, addr, td.tag_index);
            break;
        case NET_FLOW:
            taint_shadow_netflow2(shadow, env, addr, td.tag_index);
            break;
        case FILE_OBJ:
            taint_shadow_fileobj2(shadow, env, addr, td.tag_index);
            break;
        case MISC:
            taint_shadow_misc(shadow, env, addr, (misc_t)td.tag_index);
            break;
    }
}

#ifdef CCS_ENABLED
//************** TAINTING EXPORT TABLE **************//

std::unordered_map<target_ulong, target_ulong> bases;
std::unordered_map<target_ulong, target_ulong> mod_bases;

void taint_export_table(CPUState *env, target_ulong addr, uint32_t size){

    target_ulong pa = panda_virt_to_phys(env, addr);
    //faros_log << "\ntainting export table";
    for (uint32_t index = 0; index < size; index++)
        taint_shadow_misc(smem, env, pa + index, EXPORT_TABLE_TAG);
}

int read_u32(CPUState *env, target_ulong addr, uint32_t *value) {
    return panda_virtual_memory_rw(env, addr, (uint8_t *)value, 4, 0);
}

int read_u16(CPUState *env, target_ulong addr, uint16_t *value) {
    return panda_virtual_memory_rw(env, addr, (uint8_t *)value, 2, 0);
}

bool asid_loaded(target_ulong asid) {
    return bases.count(asid) != 0;
}


// Walk the list of loaded modules and add any modules and exports we haven't seen yet
void load_modules(CPUState *env, uint32_t start, uint32_t end) {
    uint8_t name_buffer[256];

    auto mods = 0;
    uint32_t ldr_cur = start;
    while(mods < 256 && ldr_cur != end) {
        uint32_t func_addr = 0, name_addr, e_lfanew, dll_base = 0;
        uint32_t funcs_arr, names_arr, ord_arr, export_table, num_ex_func;
        uint16_t ordinal = 0;

        read_u32(env, ldr_cur + 0x18, &dll_base);
        if (dll_base && !mod_bases.count(dll_base)) {
            mod_bases[dll_base] = dll_base;

            // Get ptr to nt_hdr
            read_u32(env, dll_base + 0x3c, &e_lfanew);

            // Find the export table and number of exported functions
            read_u32(env, dll_base + e_lfanew + 0x78, &export_table);
            
            // Get the size of export table
            uint32_t size_of_export_table = 0;
            read_u32(env, dll_base + e_lfanew + 0x7c, &size_of_export_table);
            
            read_u32(env, dll_base + export_table + 0x14, &num_ex_func);

            // Taint the export table
            //taint_export_table(env, dll_base + export_table, size_of_export_table);
            
            // Get Function, Name, and Ordinal array addresses
            read_u32(env, dll_base + export_table + 0x1c, &funcs_arr);
            read_u32(env, dll_base + export_table + 0x20, &names_arr);
            read_u32(env, dll_base + export_table + 0x24, &ord_arr);

            // Add location of each exported function
            for (uint32_t idx = 0; idx < num_ex_func; ++idx) {
                read_u16(env, dll_base + ord_arr + (2 * idx), &ordinal);

                if (ordinal) {
                    memset(name_buffer, 0, 256);
                    read_u32(env, dll_base + funcs_arr + (4 * ordinal), &func_addr);
                    read_u32(env, dll_base + names_arr + (4 * ordinal), &name_addr);
                    //read_n_bytes(env, dll_base + name_addr, (uint8_t *)&name_buffer, 256);
                    
                    // Taint the export table: TODO size
                    taint_export_table(env, dll_base + funcs_arr + (4 * ordinal), 4);
                    //taint_export_table(env, dll_base + func_addr, 100);
            
            
                    //name_buffer[255] = '\0';
                    //if (strlen((char *) name_buffer)) {
                    //    global_funcs[func_addr + dll_base] = std::make_shared<std::string>(std::string((char *) name_buffer));
                    //}
                }
            }
        } else {
            break;
        }
        read_u32(env, ldr_cur, &ldr_cur);
        mods++;
    }
}


// TODO Safety checks for wrong/bad PE headers
int process_module(CPUState *env) {
#if defined(TARGET_I386)
    uint32_t pid, peb, ldr, ldr_start, ldr_cur;


    auto asid = panda_current_asid(env);
    if (bases.count(asid)) {
        return 0;
    }

    auto fs = env->segs[R_FS].base;

    // Get PID and PEB from the TIB
    read_u32(env, fs + 0x20, &pid);
    read_u32(env, fs + 0x30, &peb);

    // Don't process the kernel
    //if (panda_in_kernel(env)) {
    //    return 0;
    //}
    bases[panda_current_asid(env)] = asid;

    // Get linked list of modules
    read_u32(env, peb + 0xc, &ldr);
    read_u32(env, ldr + 0xc, &ldr_cur);
    read_u32(env, ldr + 0x10, &ldr_start);

    load_modules(env, ldr_cur, ldr_start);
#endif
    return 0;
}

int before_block_exec(CPUState *env, TranslationBlock *tb) {
#if defined(TARGET_I386)
    
    // Skip the kernel because it prints a lot of extra stuff
    if (panda_in_kernel(env))
        return 0;

    // If we haven't seen this asid before load it's exports    
    if (!asid_loaded(panda_current_asid(env))) {
        process_module(env);
    }

#endif
    return 0;
}

#endif

/***** THIS FUNCTION HANDLES COMMAND LINE COMMANDS *****/

int monitor_callback(Monitor *mon, const char *cmd) {
    std::string cmd_str(cmd);

    if (cmd_str == "faros_enable") {
        monitor_printf(mon, "Enabling Faros\n");
        faros_enabled = true;
        //panda_do_flush_tb();
        /*panda_disable_tb_chaining();
        panda_enable_memcb();*/
        //panda_enable_precise_pc();
    } else if (cmd_str == "faros_disable") {
        monitor_printf(mon, "Disabling Faros\n");
        faros_enabled = false;
        //panda_do_flush_tb();
        //panda_disable_precise_pc();
        /*panda_disable_memcb();
        panda_enable_tb_chaining();*/
    } else {
        monitor_printf(mon, "Bad command!\n");
    }
    return 0;
}


////////////////////////////////////////////////////////
uint32_t reg_counter = 0;

#define NO_LABEL() std::list<taint_data_t>()
#define GET_REG_TAG(sreg, reg) sreg.count(reg) != 0 ? sreg[reg] : NO_LABEL()
#define GET_SMEM_TAG(mem, addr) mem.count(addr) != 0 ? mem[addr] : NO_LABEL()

void clear_sreg_tags(){
    sreg.clear();
}

inline void propagate_tag_union(CPUState *env, TCGArg first_arg, TCGArg second_arg, TCGArg third_arg){
   
    //sreg[first_arg] = NO_LABEL();
    //auto taint_tag = GET_REG_TAG(sreg, second_arg);

    std::list<taint_data_t> prov1 = GET_REG_TAG(sreg, second_arg);
    std::list<taint_data_t> prov2 = GET_REG_TAG(sreg, third_arg);
    if(prov1.empty() && prov2.empty()){
        sreg[first_arg].clear();
        return;
    }

    sreg[first_arg] = prov1;//GET_REG_TAG(sreg, second_arg);
    for (auto i: sreg[third_arg])
         taint_shadow(sreg, env, first_arg, i);
}

void propagate_tag_copy(TCGArg first_arg, TCGArg second_arg){
    sreg[first_arg] = GET_REG_TAG(sreg, second_arg);              
}

#define PTR uint32_t
/*
// Windows 7 offsets stolen from win7x86intro
#define EPROC_PEB_OFF 0x1a8 // _EPROCESS.Peb
#define PEB_IMAGE_BASE_ADDRESS 0x8 // _PEB.ImageBaseAddress (Reserved3[1])


PTR get_current_process_base_address(CPUState *env){
    // Get EPROCESS->PEB->ImageBaseAddress
    OsiProc *current_process = get_current_process(env);
    PTR eproc = current_process->offset;
    PTR peb = -1;
    PTR current_process_base = -1;
    panda_virtual_memory_rw(env, eproc+EPROC_PEB_OFF, (uint8_t *)&peb,
        sizeof(PTR), false);
    //assert(peb != (PTR)-1);

    panda_virtual_memory_rw(env, peb+PEB_IMAGE_BASE_ADDRESS,
        (uint8_t *)&current_process_base, sizeof(PTR), false);
    //assert(current_process_base != (PTR)-1);

    free_osiproc(current_process);
    return current_process_base;
}
*/

// typedef tcg_target_ulong TCGArg;
//typedef uint32_t tcg_target_ulong;
//./tcg/tcg.h:typedef uint64_t tcg_target_ulong;
inline int proc_ops(CPUState *env, TranslationBlock *tb) {

    //std::unordered_map<TCGArg, std::list<std::pair<target_ulong,uint32_t>>> regs;
    //const TCGContext tcg_context = tcg_ctx;
    const TCGArg *args = gen_opparam_buf;
    TCGArg arg;
    const uint16_t *ops = gen_opc_buf;
    target_ulong asid = panda_current_asid(env);
    target_ulong addr = 0;
    int op_size = 4;
    std::list<taint_data_t>::iterator it, it1;

    for (auto i = 0; ; ++i) {
        
        int noargs, niargs, ncargs;
        auto op = ops[i];
        auto def = &tcg_op_defs[op];
        if (INDEX_op_end == op) {
            break;
        }

        noargs = def->nb_oargs;
        niargs = def->nb_iargs;
        ncargs = def->nb_cargs;

        switch (op) {
            case INDEX_op_nop:
            case INDEX_op_nop1:
            case INDEX_op_nop2:
            case INDEX_op_nop3:
                break;
            case INDEX_op_nopn:
                // nopn's have a variable number of arguments
                noargs = niargs = 0;
                ncargs = *args;
                break;
            case INDEX_op_discard:
                // Marks a temp register as never being used again for current
                // block. Since the register list is cleared after each block
                // we can safely ignore this
                break;
            case INDEX_op_set_label:
                /*
                 *FORMAT: set_label $label
                 *    label: ID of label being created
                 */
                break;
            case INDEX_op_call:
                // Calls have a variable number of args that need to be calc'd
                // TODO Do we have to handle this?
                
                arg = *args++;
                noargs = arg >> 16;
                niargs = arg & 0xffff;
                ncargs = def->nb_cargs;
                break;
            case INDEX_op_jmp:
                //TODO()
                break;
            case INDEX_op_br:
                /*
                 *FORMAT: br $label
                 *    label: label defined with set_label instruction
                 *
                 * TODO Do we treat jmp and br as the same? If not how are they different?
                 */
                break;
            case INDEX_op_mov_i32:
                 propagate_tag_copy(args[0], args[1]);
                 //regs[args[0]] = GET_REG_TAG(regs, args[1]);
                 break;
            case INDEX_op_movi_i32:
                // Moves a constant value into given register.
                // Constants aren't tagged so clear the register
                sreg[args[0]].clear();// = NO_LABEL();
                //regs[args[0]] = false;
                break;
            case INDEX_op_setcond_i32:
                /*
                 * FORMAT: setcond t0, t1, t2, cond
                 * t0, t1, t2: Input registers
                 * cond: condition to check
                 *
                 * t0 = t1 cond t2
                 *
                 * TODO Decide if this propagates tags or not
                 */
            case INDEX_op_movcond_i32:
                /*
                 * FORMAT: movcond t0, t1, t2, v1, v2, cond
                 *  t0, t1, t2, v1, v2: Input registers
                 *  cond: Condition to be checked
                 *
                 *  t0 = t1 cond t2 ? v1 : v2
                 *
                 *  TODO Decide HOW, not if, this propagates tags
                 */
                break;
            /* load/store (These are from HOST memory not GUEST) */
	        case INDEX_op_st8_i32:
		        //op_size--;
            case INDEX_op_st16_i32:
		        //op_size--;
 	        case INDEX_op_st_i32:
                // TODO() How should we handle this? They deal with ld/st with HOST memory
                break;

            case INDEX_op_ld8u_i32:
            case INDEX_op_ld8s_i32:
		        //op_size--;
            case INDEX_op_ld16u_i32:
            case INDEX_op_ld16s_i32:
		        //op_size--;
            case INDEX_op_ld_i32:
                break;		           
                // TODO() How should we handle this? They deal with ld/st with HOST memory
            /* arith */
            case INDEX_op_sub_i32:		
	        case INDEX_op_add_i32:
            case INDEX_op_mul_i32:
            case INDEX_op_div_i32:
            case INDEX_op_divu_i32:
            case INDEX_op_rem_i32:
            case INDEX_op_remu_i32:
            case INDEX_op_div2_i32:
            case INDEX_op_divu2_i32:
            case INDEX_op_and_i32:
            case INDEX_op_or_i32:
                propagate_tag_union(env, args[0], args[1], args[2]);
                /*regs[args[0]] = GET_REG_TAG(regs, args[1]);//regs[args[1]];             
                
                it1 = regs[args[0]].begin();
                for (it = regs[args[2]].begin(); it!=regs[args[2]].end(); ++it)
                     //regs[args[0]].insert(it1,(*it));
                     taint_sregs(env, args[0], std::get<0>((*it)), std::get<1>((*it)));*/
                //t1 = GET_REG_TAG(regs, args[1]);
                //t2 = GET_REG_TAG(regs, args[2]);
                //regs[args[0]] = t1 | t2;
                
                break;
            case INDEX_op_xor_i32:
                //XOR'ing a value with itself zeroes it out so no taint afterwards
                if (args[1] == args[2]) {
                    sreg[args[0]].clear();// = NO_LABEL();
                    //regs[args[0]] = false;
                } else {
                    propagate_tag_union(env, args[0], args[1], args[2]);
                    /*regs[args[0]] = GET_REG_TAG(regs, args[1]);//regs[args[1]];
                    it1 = regs[args[0]].begin();
                    for (it = regs[args[2]].begin(); it!=regs[args[2]].end(); ++it)
                        regs[args[0]].insert(it1,(*it));*/
                     
                    //t1 = GET_REG_TAG(regs, args[1]);
                    //t2 = GET_REG_TAG(regs, args[2]);
                   // regs[args[0]] = t1 | t2;
                }
                break;

            /* shifts/rotates */
            case INDEX_op_shl_i32:
            case INDEX_op_shr_i32:
            case INDEX_op_sar_i32:
                // REAL TODO 
                /*t1 = GET_REG_TAG(regs, args[1]);
                t2 = GET_REG_TAG(regs, args[2]);

                if (t2 >= 32) {
                    regs[args[0]] = NO_LABEL();
                    //regs[args[0]] = false;
                } else {
                    regs[args[0]] = t1;
                }*/
                break;
            case INDEX_op_rotl_i32:
            case INDEX_op_rotr_i32:
                propagate_tag_copy(args[0], args[1]);
                //regs[args[0]] = GET_REG_TAG(regs, args[1]);// regs[args[1]];
                //t1 = GET_REG_TAG(regs, args[1]);
                //regs[args[0]] = t1;
                break;
            case INDEX_op_deposit_i32:
                propagate_tag_union(env, args[0], args[1], args[2]);
                /*regs[args[0]] = GET_REG_TAG(regs, args[1]);
                it1 = regs[args[0]].begin();
                for (it = regs[args[2]].begin(); it!=regs[args[2]].end(); ++it)
                    regs[args[0]].insert(it1,(*it));*/
                //t1 = GET_REG_TAG(regs, args[1]);
                //t2 = GET_REG_TAG(regs, args[2]);

                //regs[args[0]] = t1 | t2;
                break;
            case INDEX_op_brcond_i32:
                /*
                 * FORMAT: br_cond t0, t1, cond, label
                 *  t0, t1: Input registers
                 *  cond: Condition being checked
                 *  label: Label to jmp to if t0 cond t1 is true
                 *
                 *  TODO How to best handle this since we need to reconcile dynvals
                 */
                break;
            case INDEX_op_add2_i32:
            case INDEX_op_sub2_i32:
            case INDEX_op_brcond2_i32:
            case INDEX_op_mulu2_i32:
            case INDEX_op_setcond2_i32:
                //TODO()
                break;
            case INDEX_op_ext8s_i32:
            case INDEX_op_ext16s_i32:
            case INDEX_op_ext8u_i32:
            case INDEX_op_ext16u_i32:
                //regs[args[0]] = GET_REG_TAG(regs, args[1]);
                propagate_tag_copy(args[0], args[1]);
                break;
            case INDEX_op_bswap16_i32:
            case INDEX_op_bswap32_i32:
                //regs[args[0]] = GET_REG_TAG(regs, args[1]);
                propagate_tag_copy(args[0], args[1]);
                break;
            case INDEX_op_not_i32:
                //regs[args[0]] = GET_REG_TAG(regs, args[1]);
                propagate_tag_copy(args[0], args[1]);
                break;
            case INDEX_op_neg_i32:
            case INDEX_op_andc_i32:
            case INDEX_op_orc_i32:
            case INDEX_op_eqv_i32:
            case INDEX_op_nand_i32:
            case INDEX_op_nor_i32:
                propagate_tag_union(env, args[0], args[1], args[2]);
                /*regs[args[0]] = GET_REG_TAG(regs, args[1]);
                it1 = regs[args[0]].begin();
                for (it = regs[args[2]].begin(); it!=regs[args[2]].end(); ++it)
                    regs[args[0]].insert(it1,(*it));*/
                //t1 = GET_REG_TAG(regs, args[1]);
                //t2 = GET_REG_TAG(regs, args[2]);

                //regs[args[0]] = t1 | t2;
                break;

                //64 bit instructions
            case INDEX_op_mov_i64:
                propagate_tag_copy(args[0], args[1]);
                //regs[args[0]] = GET_REG_TAG(regs, args[1]);
                break;
            case INDEX_op_movi_i64:
                sreg[args[0]].clear();// = NO_LABEL();
                break;
            case INDEX_op_setcond_i64:
            case INDEX_op_movcond_i64:
                //TODO()
                break;

            /* load/store */
            // These are Loads/Store from HOST to GUEST memory
            case INDEX_op_ld8u_i64:
            case INDEX_op_ld8s_i64:
            case INDEX_op_ld16u_i64:
            case INDEX_op_ld16s_i64:
            case INDEX_op_ld32u_i64:
            case INDEX_op_ld32s_i64:
            case INDEX_op_ld_i64:            
            case INDEX_op_st8_i64:
            case INDEX_op_st16_i64:
            case INDEX_op_st32_i64:
            case INDEX_op_st_i64:
                //TODO() How should we handle these since they deal with HOST memory?
                break;

            /* arith */
            // case INDEX_op_add_i64:
            case INDEX_op_sub_i64:
            case INDEX_op_add_i64:
            case INDEX_op_mul_i64:
            case INDEX_op_div_i64:
            case INDEX_op_divu_i64:
            case INDEX_op_rem_i64:
            case INDEX_op_remu_i64:
            case INDEX_op_div2_i64:
            case INDEX_op_divu2_i64:
            case INDEX_op_and_i64:
            case INDEX_op_or_i64:
                propagate_tag_union(env, args[0], args[1], args[2]);
                /*regs[args[0]] = GET_REG_TAG(regs, args[1]);
                it1 = regs[args[0]].begin();
                for (it = regs[args[2]].begin(); it!=regs[args[2]].end(); ++it)
                    regs[args[0]].insert(it1,(*it));*/
                //t1 = GET_REG_TAG(regs, args[1]);
                //t2 = GET_REG_TAG(regs, args[2]);

                //regs[args[0]] = t1 | t2;
                break;

            case INDEX_op_xor_i64:
                //XOR'ing a value with itself zeroes it out so no taint afterwards
                if (args[1] == args[2]) {
                    sreg[args[0]].clear();// = NO_LABEL();
                } else {
                    propagate_tag_union(env, args[0], args[1], args[2]);
                    /*regs[args[0]] = GET_REG_TAG(regs, args[1]);
                    it1 = regs[args[0]].begin();
                    for (it = regs[args[2]].begin(); it!=regs[args[2]].end(); ++it)
                        regs[args[0]].insert(it1,(*it));*/
                    //t1 = GET_REG_TAG(regs, args[1]);
                    //t2 = GET_REG_TAG(regs, args[2]);

                    //regs[args[0]] = t1 | t2;
                }
                break;

            /* shifts/rotates */
            case INDEX_op_shl_i64:
            case INDEX_op_shr_i64:
            case INDEX_op_sar_i64:
                // REAL TODO
                /*t1 = GET_REG_TAG(regs, args[1]);
                t2 = GET_REG_TAG(regs, args[2]);

                if (t2 >= 64) {
                    regs[args[0]] = false;
                } else {
                    regs[args[0]] = t1;
                }*/
                break;
            case INDEX_op_rotl_i64:
            case INDEX_op_rotr_i64:
                propagate_tag_copy(args[0], args[1]);
                //regs[args[0]] = GET_REG_TAG(regs, args[1]);
                //t1 = GET_REG_TAG(regs, args[1]);
                //regs[args[0]] = t1;
                break;
            case INDEX_op_deposit_i64:
                propagate_tag_union(env, args[0], args[1], args[2]);
                /*regs[args[0]] = GET_REG_TAG(regs, args[1]);
                it1 = regs[args[0]].begin();
                for (it = regs[args[2]].begin(); it!=regs[args[2]].end(); ++it)
                    regs[args[0]].insert(it1,(*it));*/
                //t1 = GET_REG_TAG(regs, args[1]);
                //t2 = GET_REG_TAG(regs, args[2]);

                //regs[args[0]] = t1 | t2;
                break;
            case INDEX_op_brcond_i64:
                //TODO()
                break;
            case INDEX_op_ext8s_i64:
            case INDEX_op_ext16s_i64:
            case INDEX_op_ext32s_i64:
            case INDEX_op_ext8u_i64:
            case INDEX_op_ext16u_i64:
            case INDEX_op_ext32u_i64:
                propagate_tag_copy(args[0], args[1]);
                //regs[args[0]] = GET_REG_TAG(regs, args[1]);
                break;
            case INDEX_op_bswap16_i64:
            case INDEX_op_bswap32_i64:
            case INDEX_op_bswap64_i64:
                propagate_tag_copy(args[0], args[1]);
                //regs[args[0]] = GET_REG_TAG(regs, args[1]);
                break;
            case INDEX_op_not_i64:
            case INDEX_op_neg_i64:
            case INDEX_op_andc_i64:
            case INDEX_op_orc_i64:
            case INDEX_op_eqv_i64:
            case INDEX_op_nand_i64:
            case INDEX_op_nor_i64:

            /* QEMU specific */
            case INDEX_op_debug_insn_start:
            case INDEX_op_exit_tb:
                /*
                 * FORMAT: exit_tb t0
                 *  t0: Register holding return value
                 *
                 *  Same as return t0 in C
                 */
            case INDEX_op_goto_tb:
                /*
                 * FORMAT: goto_tb $index
                 *  index: Index number of next TB to go to
                 *
                 *  Jumps to the TB specified by $index.
                 *  Only 0 and 1 are valid values for $index
                 *
                 *  Since we turn off chaining we don't use this
                 *
                 */
                // TODO Do we have to handle these?
                break;
            case INDEX_op_qemu_ld8u:
            case INDEX_op_qemu_ld8s:
                op_size--;
            case INDEX_op_qemu_ld16u:
            case INDEX_op_qemu_ld16s:
                op_size--;
            case INDEX_op_qemu_ld32:
            case INDEX_op_qemu_ld64:
                if (!reads[asid].empty()) {
                    addr = reads[asid].front();

                    reads[asid].pop();

                    #ifdef CCS_ENABLED
                    check_for_potential_injection_attack(env, addr, /*env->panda_guest_pc*/tb->pc, tb->size);
                    #endif
                    //sreg[args[0]] = GET_SMEM_TAG(smem, addr);
			        //sreg[args[0]].clear();
                    for (auto x = 1; x < op_size; x++) {
                        //it1 = sreg[args[0]].begin();
                        
                        std::list<taint_data_t> tag_list = GET_SMEM_TAG(smem, addr + x);
                        if(tag_list.empty())
			                continue;

                        for (auto i: tag_list)
                            taint_shadow(sreg, env, args[0], i);

                    }
                }
                op_size = 4;
                break;

            // TODO Clean up these cases and simplify
            case INDEX_op_qemu_st8:
                op_size--;
            case INDEX_op_qemu_st16:
                op_size--;
            case INDEX_op_qemu_st32:
            case INDEX_op_qemu_st64:
                if (!writes[asid].empty()) {
                    addr = writes[asid].front();

                    writes[asid].pop();
                    //addr = args[1];
                    for (auto x = 0; x < op_size; x++) {
                        //smem[addr + x] = GET_REG_TAG(sreg, args[1]);
			            std::list<taint_data_t> tag_list = GET_REG_TAG(sreg, args[1]);
			            if(tag_list.empty())
			                continue;
			            //smem[addr+x].clear();
			            for (auto i: tag_list)
			                taint_shadow(smem, env, addr + x, i);

                    }
                }
                op_size = 4;
                break;
            default:
                //TODO()
                break;
        }
        args += niargs + noargs + ncargs;
    }
    return 0;
}


////////////////////////////////////////////////////////
/***** THIS PART HANDLES TAINT PROPAGATION *****/

//#define REG_TAINT_EXPIRATION 100

int after_block_exec(CPUState *env, TranslationBlock *tb,
                     TranslationBlock *next_tb) {
    if(!tag_kernel){
        if (!faros_enabled || panda_in_kernel(env)) {
            return 0;
        }
    }
    target_ulong asid = panda_current_asid(env);
    proc_ops(env, tb);

    /*if(reg_counter++ == REG_TAINT_EXPIRATION){
        clear_sreg_tags();
        reg_counter = 0;
    }*/
    // TODO See if there is a more efficient way of doing this  
    reads[asid] = {};
    writes[asid] = {};
    return 0;
}

int phys_read_callback(CPUState *env, target_ulong pc, target_ulong addr,
                       target_ulong size, void *buf) {

    target_ulong asid = panda_current_asid(env); 
    if(!tag_kernel && panda_in_kernel(env)){
            //asid = 1;
            //for (target_ulong i=0; i < size; i++)
            //    taint_smem_cr3(env, addr + i, asid);
            return 0;
    }
    if (0 == reads.count(asid))
        reads[asid] = std::queue<target_ulong>();

    reads[asid].push(addr);
    for (target_ulong i=0; i < size; i++)
       taint_shadow_cr3(smem, env, addr + i, asid);
    return 0;
}

int phys_write_callback(CPUState *env, target_ulong pc, target_ulong addr,
                        target_ulong size, void *buf) {

    target_ulong asid = panda_current_asid(env);
    if(!tag_kernel && panda_in_kernel(env)){
            //asid = 2;
            //for (target_ulong i=0; i < size; i++)
            //   taint_smem_cr3(env, addr + i, asid);
            return 0;
    }
    if (0 == writes.count(asid))
       writes[asid] = std::queue<target_ulong>();

    writes[asid].push(addr);
    for (target_ulong i=0; i < size; i++)
       taint_shadow_cr3(smem, env, addr + i, asid);
    return 0;
}


/*
int faros_net_send(CPUState *env, uint64_t src_addr, uint32_t num_bytes) {

    if (!faros_enabled || !taint_enabled) // || (!tag_kernel && panda_in_kernel(env))) 
        return 0;

    for (size_t x = 0; x < num_bytes; x++){
        //smem[dst_addr + x] = true;
	    //taint_smem_cr3( env, (target_ulong)src_addr + x, 0);
    }
    return 0;
}

int faros_net_recv(CPUState *env, uint64_t dst_addr, uint32_t num_bytes) {
    faros_log << "\ninside faros_net_recv 1";
    if (!faros_enabled || (!tag_kernel && panda_in_kernel(env))) 
        return 0;
    faros_log << "\ninside faros_net_recv";

    return 0;
}
*/


/***** ThIS PART IS IMPORTED AND MODIFIED FROM WIN7PROC PLUGIN *****/
// it enables us to convert a file handle to a file name

#define KMODE_FS           0x030
#define KPCR_CURTHREAD_OFF 0x124
#define KTHREAD_KPROC_OFF  0x150
#define EPROC_NAME_OFF     0x16c

// Win7 Obj Type Indices
typedef enum {
    OBJ_TYPE_Process = 7,
    OBJ_TYPE_File = 28,
    OBJ_TYPE_Key = 35,
} OBJ_TYPES;

typedef struct handle_object_struct {
    uint8_t objType;
    uint32_t pObj;
} HandleObject;

static void get_procname(CPUState *env, target_ulong eproc, char *name) {
    panda_virtual_memory_rw(env, eproc+EPROC_NAME_OFF, (uint8_t *)name, 15, false);
    name[16] = '\0';
}

static uint32_t get_current_proc(CPUState *env) {
    // Read the kernel-mode FS segment base
    uint32_t e1, e2;
    uint32_t fs_base, thread, proc;

    // Read out the two 32-bit ints that make up a segment descriptor
    panda_virtual_memory_rw(env, env->gdt.base + KMODE_FS, (uint8_t *)&e1, 4, false);
    panda_virtual_memory_rw(env, env->gdt.base + KMODE_FS + 4, (uint8_t *)&e2, 4, false);
    
    // Turn wacky segment into base
    fs_base = (e1 >> 16) | ((e2 & 0xff) << 16) | (e2 & 0xff000000);

    // Read KPCR->CurrentThread->Process
    panda_virtual_memory_rw(env, fs_base+KPCR_CURTHREAD_OFF, (uint8_t *)&thread, 4, false);
    panda_virtual_memory_rw(env, thread+KTHREAD_KPROC_OFF, (uint8_t *)&proc, 4, false);

    return proc;
}

#define EPROC_OBJTABLE_OFF     0xf4

#define HANDLE_MASK1  0x000007fc
#define HANDLE_SHIFT1  2
#define HANDLE_MASK2  0x001ff800
#define HANDLE_SHIFT2  11
#define HANDLE_MASK3  0x7fe00000
#define HANDLE_SHIFT3  21
#define LEVEL_MASK 0x00000007
#define TABLE_MASK ~LEVEL_MASK
#define ADDR_SIZE 4
#define HANDLE_TABLE_ENTRY_SIZE 8

uint32_t handle_table_code(CPUState *env, uint32_t table_vaddr) {
    uint32_t tableCode;
    panda_virtual_memory_rw(env, table_vaddr, (uint8_t *)&tableCode, 4, false);
    return (tableCode & TABLE_MASK);
}

uint32_t handle_table_L1_addr(CPUState *env, uint32_t table_vaddr, uint32_t entry_num) {
    return handle_table_code(env, table_vaddr) + ADDR_SIZE * entry_num;
}

uint32_t handle_table_L2_addr(uint32_t L1_table, uint32_t L2) {
    if (L1_table != 0x0) {
        uint32_t L2_entry = L1_table + ADDR_SIZE * L2;
        return L2_entry;
    }
    return 0;
}

uint32_t handle_table_L1_entry(CPUState *env, uint32_t table_vaddr, uint32_t entry_num) {
    return (handle_table_code(env, table_vaddr) +	
            HANDLE_TABLE_ENTRY_SIZE * entry_num);
}

uint32_t handle_table_L2_entry(uint32_t table_vaddr, uint32_t L1_table, uint32_t L2) {
    if (L1_table == 0) return 0;
    return L1_table + HANDLE_TABLE_ENTRY_SIZE * L2;          
}

uint32_t handle_table_L3_entry(uint32_t table_vaddr, uint32_t L2_table, uint32_t L3) {
    if (L2_table == 0) return 0;
    return L2_table + HANDLE_TABLE_ENTRY_SIZE * L3;
}

// i.e. return pointer to the object represented by this handle
uint32_t get_handle_table_entry(CPUState *env, uint32_t pHandleTable, uint32_t handle) {
    uint32_t tableCode, tableLevels;
    // get tablecode
    panda_virtual_memory_rw(env, pHandleTable, (uint8_t *)&tableCode, 4, false);
    tableLevels = tableCode & LEVEL_MASK;  
    if (tableLevels > 2) {
        return 0;
    }
    uint32 pEntry=0;
    if (tableLevels == 0) {
        uint32_t index = (handle & HANDLE_MASK1) >> HANDLE_SHIFT1;
        pEntry = handle_table_L1_entry(env, pHandleTable, index);
    }
    if (tableLevels == 1) {
        uint32_t L1_index = (handle & HANDLE_MASK2) >> HANDLE_SHIFT2;
        uint32_t L1_table_off = handle_table_L1_addr(env, pHandleTable, L1_index);
        uint32_t L1_table;
        panda_virtual_memory_rw(env, L1_table_off, (uint8_t *) &L1_table, 4, false);
        uint32_t index = (handle & HANDLE_MASK1) >> HANDLE_SHIFT1;
        pEntry = handle_table_L2_entry(pHandleTable, L1_table, index);
    }
    if (tableLevels == 2) {
        uint32_t L1_index = (handle & HANDLE_MASK3) >> HANDLE_SHIFT3;
        uint32_t L1_table_off = handle_table_L1_addr(env, pHandleTable, L1_index);
        uint32_t L1_table;
        panda_virtual_memory_rw(env, L1_table_off, (uint8_t *) &L1_table, 4, false);
        uint32_t L2_index = (handle & HANDLE_MASK2) >> HANDLE_SHIFT2;
        uint32_t L2_table_off = handle_table_L2_addr(L1_table, L2_index);
        uint32_t L2_table;
        panda_virtual_memory_rw(env, L2_table_off, (uint8_t *) &L2_table, 4, false);
        uint32_t index = (handle & HANDLE_MASK1) >> HANDLE_SHIFT1;
        pEntry = handle_table_L3_entry(pHandleTable, L2_table, index);
    }
    uint32_t pObjectHeader;
    if ((panda_virtual_memory_rw(env, pEntry, (uint8_t *) &pObjectHeader, 4, false)) == -1) {
        return 0;
    }
    //  printf ("processHandle_to_pid pObjectHeader = 0x%x\n", pObjectHeader);
    pObjectHeader &= ~0x00000007;

    return pObjectHeader;
}

// Hack
static void unicode_to_ascii(char *uni, char *ascii, int len) {
    for (int i = 0; i < len; i++) {
        ascii[i] = uni[i*2];
    }
}

static char *read_unicode_string(CPUState *env, target_ulong pUstr) {
    uint16_t fileNameLen;
    uint32_t fileNamePtr;
    char *fileName = (char *)calloc(1, 260);
    char fileNameUnicode[260*2] = {};

    panda_virtual_memory_rw(env, pUstr,
            (uint8_t *) &fileNameLen, 2, false);
    panda_virtual_memory_rw(env, pUstr+4,
            (uint8_t *) &fileNamePtr, 4, false);

    if (fileNameLen > 259*2) {
        fileNameLen = 259*2; 
    }
    panda_virtual_memory_rw(env, fileNamePtr, (uint8_t *)fileNameUnicode, fileNameLen, false);
    unicode_to_ascii(fileNameUnicode, fileName, fileNameLen/2);

    return fileName;
}

#define FILE_OBJECT_NAME_OFF 0x30
static char *get_file_obj_name(CPUState *env, uint32_t fobj) {
    return read_unicode_string(env, fobj+FILE_OBJECT_NAME_OFF);
}

static HandleObject *get_handle_object(CPUState *env, uint32_t eproc, uint32_t handle) {
    uint32_t pObjectTable;
    if (-1 == panda_virtual_memory_rw(env, eproc+EPROC_OBJTABLE_OFF, (uint8_t *)&pObjectTable, 4, false)) {
        return NULL;
    }
    uint32_t pObjHeader = get_handle_table_entry(env, pObjectTable, handle);
    if (pObjHeader == 0) return NULL;
    uint32_t pObj = pObjHeader + 0x18;
    uint8_t objType = 0;
    if (-1 == panda_virtual_memory_rw(env, pObjHeader+0xc, &objType, 1, false)) {
        return NULL;
    }
    HandleObject *ho = (HandleObject *) malloc(sizeof(HandleObject));
    ho->objType = objType;
    ho->pObj = pObj;
    return ho;
}

static char *get_handle_object_name(CPUState *env, HandleObject *ho) {
    if (ho == NULL){
        char *procName = (char *) calloc(8, 1);
	    sprintf(procName, "unknown");
        return procName;
    }
    switch (ho->objType) {
        case OBJ_TYPE_File:
            return get_file_obj_name(env, ho->pObj);
        case OBJ_TYPE_Key: {
            char *fileName = (char *) calloc(100, 1);
            sprintf(fileName, "_CM_KEY_BODY@%08x", ho->pObj);
            return fileName;
        }
	  break;
        case OBJ_TYPE_Process: {
            char *procName = (char *) calloc(100, 1);
            get_procname(env, ho->pObj, procName);
            return procName;
        }
            break;
        default:
	  char *procName = (char *) calloc(8, 1);
	    sprintf(procName, "unknown");
	    return procName;
    }
}

static char * get_handle_name(CPUState *env, uint32_t eproc, uint32_t handle) {
    HandleObject *ho = get_handle_object(env, eproc, handle);
    return get_handle_object_name(env, ho);
}



/***** THIS PART CAPTURES A SYSCALL AND SAVES ITS INFO *****/

bool is_this_process_filtered(uint32_t pid, char *process_name, uint32_t pname_len){
    
    uint32_t i;
    for (i = 0; i < pnames.count; i++)
        if (0 == strncmp(pnames.pname[i].c_str(), process_name, pname_len))
            return true;
    for (i = 0; i < pids.count; i++)
        if (pids.pid[i] == pid)
            return true;
    return false;
}

inline long long get_current_timestamp() {
    struct timeval te; 
    gettimeofday(&te, NULL); // get current time
    long long milliseconds = te.tv_sec*1000LL + te.tv_usec/1000; // caculate milliseconds
    return milliseconds;
}

// Convert a FileHandle to a file object
file_obj_t * filehandle_to_fileobject(CPUState* env, uint32_t FileHandle) {

    char *fileName = get_handle_name(env, get_current_proc(env), FileHandle);
    if (!fileName || strlen(fileName) < 2)
       return NULL;
    file_obj_t *fo = (FileObject *)calloc(sizeof(FileObject), 1);
    if (!fo)
       return NULL;
    std::string fn_str(fileName);

    fo->filename = fileName;
    if (file_access.count(fn_str) == 0)
        file_access[fn_str] = 1;
    else
        file_access[fn_str] += 1;
    fo->version = file_access[fn_str];

    return fo;
    /*for(uint32_t byte_indx = 0; byte_indx < BufferLength; byte_indx++){
        pa = panda_virt_to_phys(env, Buffer + byte_indx);
        taint_smem_fileObject(env, pa, fo);
    }*/
}


#define NtCancelIoFile 45
#define NtCancelIoFileEx 46
#define NtCreateSection 84
#define NtFlushBuffersFile 123
#define NtLockFile 159
#define NtNotifyChangeDirectoryFile 171
#define NtQueryDirectoryFile 223
#define NtQueryEaFile 226
#define NtQueryInformationFile 231
#define NtQueryQuotaInformationFile 253
#define NtQueryVolumeInformationFile 268
#define NtReadFile 273
#define NtReadFileScatter 274
#define NtRestoreKey 302
#define NtSaveKey 309
#define NtSaveKeyEx 310
#define NtSaveMergedKeys 311
#define NtSetEaFile 322
#define NtSetInformationFile 329
#define NtSetQuotaInformationFile 346
#define NtSetVolumeInformationFile 359
#define NtUnlockFile 383
#define NtWriteFile 396
#define NtWriteFileGather 397

#define NtCreateFile 66
#define NtOpenDirectoryObject 175
#define NtOpenFile 179
#define NtDeviceIoControlFile_CALL_NO 107

// list of system call numbers that has a PFileHandle argument
#define PFILEHANDLE_LIST_SIZE 3
uint32_t pfilehandle_syscall_no[] = {NtCreateFile, NtOpenDirectoryObject, NtOpenFile};

// list of system call numbers that has a FileHandle argument
#define FILEHANDLE_LIST_SIZE 24
uint32_t filehandle_syscall_no[] = {NtCancelIoFile, NtCancelIoFileEx, NtCreateSection, NtFlushBuffersFile, \
                                    NtLockFile, NtNotifyChangeDirectoryFile, NtQueryDirectoryFile, NtQueryEaFile, \
                                    NtQueryInformationFile, NtQueryQuotaInformationFile, NtQueryVolumeInformationFile, \
                                    NtReadFile, NtReadFileScatter, NtRestoreKey, NtSaveKey, NtSaveKeyEx, \
                                    NtSaveMergedKeys, NtSetEaFile, NtSetInformationFile, NtSetQuotaInformationFile, \
                                    NtSetVolumeInformationFile, NtUnlockFile, NtWriteFile, NtWriteFileGather};

// Return the filehandle argument number of a system call
uint32_t get_filehandle_arg_no(target_ulong syscall_no){

    switch(syscall_no){
        case NtCreateSection:
            return 7;
        case NtRestoreKey:
        case NtSaveKey:
        case NtSaveKeyEx:
            return 2;
        case NtSaveMergedKeys:
            return 3;
        default:
            return 1;
    }
}

// Check if the current system call has a FileHandle argument
bool this_syscall_has_a_filehandle(target_ulong syscall_no){

    for(int i = 0; i < FILEHANDLE_LIST_SIZE; i++)
        if (filehandle_syscall_no[i] == syscall_no)
            return true;
    return false;
}

// Add a file object to the current syscall
void add_file_object(CPUState *env, target_ulong syscalls_info_index){

    uint32_t arg_number = get_filehandle_arg_no(syscalls_info[syscalls_info_index].syscall_no);
    uint32_t filehandle = *((uint32_t *)syscalls_info[syscalls_info_index].args[arg_number-1].arg1);
    file_obj_t *fo = filehandle_to_fileobject(env, filehandle);
    syscalls_info[syscalls_info_index].fo = fo;
}

void taint_net(CPUState *env, char *buffer, uint32_t buff_size, target_ulong org_buffer_addr, uint32_t org_buffer_size, cr3_t cr3){

    if (buff_size < 14)
        return;

    if (0 == strncmp(buffer, "IOCTL_AFD_SEND", 14)) {
        //faros_log << "\nIOCTL_AFD_SEND len: " << org_buffer_size;
        target_ulong pa = panda_virt_to_phys(env, org_buffer_addr);
        for(uint32_t index = 0; index < org_buffer_size; index++){
            taint_shadow_misc(smem, env, pa + index, OUTGOING_FLOW_TAG);
            //taint_shadow_cr3(smem, env, pa + index, cr3);
        }
    }
    else if (0 == strncmp(buffer, "IOCTL_AFD_RECV", 14)) {
        //faros_log << "\nIOCTL_AFD_RECV len: " << org_buffer_size;
        target_ulong pa = panda_virt_to_phys(env, org_buffer_addr);
        for(uint32_t index = 0; index < org_buffer_size; index++){
            taint_shadow_misc(smem, env, pa + index, INCOMING_FLOW_TAG);
            //taint_shadow_cr3(smem, env, pa + index, cr3);
        }
    }
    else if (buff_size > 22 && 0 == strncmp(buffer, "IOCTL_AFD_SEND_DATAGRAM", 23)) {
        //faros_log << "\nIOCTL_AFD_SEND_DATAGRAM len: " << org_buffer_size;
        target_ulong pa = panda_virt_to_phys(env, org_buffer_addr);
        for(uint32_t index = 0; index < org_buffer_size; index++){
            taint_shadow_misc(smem, env, pa + index, OUTGOING_FLOW_TAG);
            //taint_shadow_cr3(smem, env, pa + index, cr3);
        }
    }
    else if (buff_size > 22 && 0 == strncmp(buffer, "IOCTL_AFD_RECV_DATAGRAM", 23)) {
        //faros_log << "\nIOCTL_AFD_RECV_DATAGRAM len: " << org_buffer_size;
        target_ulong pa = panda_virt_to_phys(env, org_buffer_addr);
        for(uint32_t index = 0; index < org_buffer_size; index++){
            taint_shadow_misc(smem, env, pa + index, INCOMING_FLOW_TAG);
            //taint_shadow_cr3(smem, env, pa + index, cr3);
        }
    }
    else
        return;
    //faros_log << buffer << " -> end\n";
}
   
    
inline int add_syscall_info(CPUState *env, target_ulong callno, syscall_args SyscallArgs, cr3_t cr3){

	uint32_t i;
	    
	if (syscalls_info_count >= MAX_SYSCALL_NO)
	    return 0;
    OsiProc *current = get_current_process(env);

	if (cr3_to_processinfo.count(cr3) == 0){
        if (rolling == true){
            pthread_mutex_lock(&thread_lock);
           // Add new cr3 to the global list
           cr3_to_processinfo[cr3].pid = current->pid;
           cr3_to_processinfo[cr3].ppid = current->ppid;
           cr3_to_processinfo[cr3].process_name = std::string(current->name, strlen(current->name));
           pthread_mutex_unlock(&thread_lock);
        }
        else{
            cr3_to_processinfo[cr3].pid = current->pid;
            cr3_to_processinfo[cr3].ppid = current->ppid;
            cr3_to_processinfo[cr3].process_name = std::string(current->name, strlen(current->name));
        }
    }   

    if ((pids.count == 0 && pnames.count == 0) || is_this_process_filtered(current->pid, current->name, strlen(current->name))){
        if (rolling == true)
            pthread_mutex_lock(&thread_lock);
	    syscalls_info[syscalls_info_count].syscall_no = callno;
        
	    // Set syscall arguments 
        for (i = 0; i < SyscallArgs.arg_number; i++){
		        if(SyscallArgs.args[i].size1 == 0){
                    syscalls_info[syscalls_info_count].args[i].size1 = 0;
                    syscalls_info[syscalls_info_count].args[i].size2 = 0;
			        continue;
		        }		    

		        syscalls_info[syscalls_info_count].args[i].arg1 = SyscallArgs.args[i].arg1;
		        syscalls_info[syscalls_info_count].args[i].size1 = SyscallArgs.args[i].size1;
		        syscalls_info[syscalls_info_count].args[i].address = panda_virt_to_phys(env, SyscallArgs.args[i].address);
		        syscalls_info[syscalls_info_count].args[i].string_flag =  SyscallArgs.args[i].string_flag;
		        syscalls_info[syscalls_info_count].args[i].pointer_flag =  SyscallArgs.args[i].pointer_flag;
		        syscalls_info[syscalls_info_count].args[i].pointer_value1 = panda_virt_to_phys(env, SyscallArgs.args[i].pointer_value1);
		        syscalls_info[syscalls_info_count].args[i].pointer_size1 = SyscallArgs.args[i].pointer_size1;	
		        syscalls_info[syscalls_info_count].args[i].pointer_size2 = 0;			
		        syscalls_info[syscalls_info_count].args[i].size2 = 0;		    

		        if(SyscallArgs.args[i].size2 == 0)
			        continue;
		        
		        syscalls_info[syscalls_info_count].args[i].arg2 = SyscallArgs.args[i].arg2;
		        syscalls_info[syscalls_info_count].args[i].size2 = SyscallArgs.args[i].size2;
		        syscalls_info[syscalls_info_count].args[i].pointer_value2 = panda_virt_to_phys(env, SyscallArgs.args[i].pointer_value2);
		        syscalls_info[syscalls_info_count].args[i].pointer_size2 = SyscallArgs.args[i].pointer_size2;

	    }
        syscalls_info[syscalls_info_count].args_number = SyscallArgs.arg_number;
        syscalls_info[syscalls_info_count].retval = SyscallArgs.retval;
        syscalls_info[syscalls_info_count].cr3 = cr3;
        syscalls_info[syscalls_info_count].timestamp = get_current_timestamp();
        
        // Add Netflow object, if there is any
        if (callno == NtDeviceIoControlFile_CALL_NO){
            target_ulong org_buffer_addr = SyscallArgs.args[6].pointer_value2;
            uint32_t org_buffer_size = SyscallArgs.args[6].pointer_size2;
            char *buffer = (char *)syscalls_info[syscalls_info_count].args[6].arg2;
            uint32_t buffer_size = SyscallArgs.args[6].size2;
            taint_net(env, buffer, buffer_size, org_buffer_addr, org_buffer_size, cr3);
        }
        // Add file objects to the current syscall, if there is any
        if (this_syscall_has_a_filehandle(callno))
           add_file_object(env, syscalls_info_count);
    
        syscalls_info_count++;
        
        if (rolling == true)
            pthread_mutex_unlock(&thread_lock);
    }
    free_osiproc(current);


	return 1;
}

void all_syscall_return(CPUState *env, target_ulong pc, target_ulong callno, syscall_args SyscallArgs){

    //if (panda_in_kernel(env))
    //    return;
    uint32_t i, byte_indx;
    if (faros_enabled){
	    //target_ulong cr3;// = (target_ulong *)malloc(sizeof(target_ulong));
	    cr3_t cr3 = panda_current_asid(env);
	     add_syscall_info(env, callno, SyscallArgs, cr3);
	    if (taint_enabled){
		    // Taint the memory
	        for (i = 0; i < SyscallArgs.arg_number; i++){
		        if( SyscallArgs.args[i].size1 <= 10000 ){                
		            uint32_t pa;
			        for (byte_indx = 0 ; byte_indx < SyscallArgs.args[i].pointer_size1;  byte_indx++){
                        pa = panda_virt_to_phys(env, SyscallArgs.args[i].pointer_value1 + byte_indx);
                        // label this phys addr in memory with label l
                        taint_shadow_cr3(smem, env, pa, cr3);
                    }
			        for (byte_indx = 0 ; byte_indx < SyscallArgs.args[i].pointer_size2;  byte_indx++){
			             pa = panda_virt_to_phys(env, SyscallArgs.args[i].pointer_value2 + byte_indx);
			             taint_shadow_cr3(smem, env, pa, cr3);
                    }
			        if(SyscallArgs.args[i].pointer_flag == false && SyscallArgs.args[i].string_flag == false)
				         for (byte_indx = 0 ; byte_indx < SyscallArgs.args[i].size1;  byte_indx++){
				         	 pa = panda_virt_to_phys(env, SyscallArgs.args[i].address + byte_indx);
				         	 taint_shadow_cr3(smem, env, pa, cr3);
                         }
		        }// end if
            }// end for
 	    } // end if
	}// end if
}

/***** THIS PART HANDLES AN INCOMING/OUTGOING PACKET AND TAINTS THE PACKET CONTENT ACCORDINGLY *****/

void get_ip_header(unsigned char* Buffer, int Size)
{
    struct sockaddr_in source,dest;
    struct iphdr *iph = (struct iphdr *)(Buffer+14);
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    //faros_log << "   |-Source IP        :" << inet_ntoa(source.sin_addr) << "\n";
    //faros_log << "   |-Destination IP   :" << inet_ntoa(dest.sin_addr) << "\n";
}


void get_netflow_obj(unsigned char *Buffer , int Size, net_flow_t &nf)
{
    unsigned short iphdrlen;  
    struct iphdr *iph = (struct iphdr *)(Buffer + 14);
    
    //iphdrlen = iph->ihl*4;
    
    // retireve the position of the udp header 
    iphdrlen = (iph->ihl & 0xf) * 4;
    struct udphdr *udph = (struct udphdr*) ((u_char*)iph + iphdrlen);
     
    get_ip_header(Buffer,Size); 
    struct sockaddr_in source,dest;
    //struct iphdr *iph = (struct iphdr *)(Buffer+14);
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    char *src_ip = inet_ntoa(source.sin_addr);
    nf.src_ip = (char *)calloc(strlen(src_ip) + 1, 1);
    strcpy(nf.src_ip, src_ip);
    
    char *des_ip = inet_ntoa(dest.sin_addr);
    nf.des_ip = (char *)calloc(strlen(des_ip) + 1, 1);
    strcpy(nf.des_ip, des_ip);
    
    //faros_log << "   |-Source IP        :" << inet_ntoa(source.sin_addr) << "\n";
    //faros_log << "   |-Destination IP   :" << inet_ntoa(dest.sin_addr) << "\n";

    nf.src_port = ntohs(udph->source);
    nf.des_port = ntohs(udph->dest);
    
    //faros_log << "   |-Source Port      :" << ntohs(udph->source) << "\n";
    //faros_log << "   |-Destination Port :" << ntohs(udph->dest) << "\n";
    
}
/*
// old_buf_addr specifies the (host) address that the network buffer had during the recording
int handle_packet(CPUState *env, uint8_t *buf, int size, uint8_t direction,
        uint64_t old_buf_addr){

    if(!taint_enabled)
        return 0;
    
    // Get the IP Header part of this packet
    struct iphdr *iph = (struct iphdr*)(buf + 14);
    NetflowObjectP nfo = NULL;
    switch (iph->protocol) // Check the Protocol and do accordingly...
    {
        case 1:  // ICMP Protocol
            break;
         
        case 2:  // IGMP Protocol
            break;
         
        case 6:  // TCP Protocol
            nfo = get_netflow_obj((unsigned char *)buf , size);
            nfo->proto = iph->protocol;
            break;
         
        case 17: // UDP Protocol
            nfo = get_netflow_obj((unsigned char *)buf , size);
            nfo->proto = iph->protocol;
            break;
         
        default: // Some Other Protocol like ARP etc.
            break;
    }
    
    if (nfo){ // Taint net flow bytes with the captured netflow object
        uint32_t addr = (uint32_t)(*((uint32_t *)(&buf)));
        for(int byte_indx = 0; byte_indx < size; byte_indx++){
            target_ulong pa = panda_virt_to_phys(env, addr + byte_indx);
            taint_smem_netFlowObject(env, pa, nfo);
        }
    }
    return 0;
}
*/

/* this is for much of the network taint transfers.
 * src_addr/dest_addr addresses are physical addresses
 */

int cb_replay_net_transfer(CPUState *env, uint32_t type, uint64_t src_addr,
        uint64_t dest_addr, uint32_t num_bytes){
    // Replay network transfer as taint transfer
    
    struct iphdr *iph;
    net_flow_t nfo;
    bool nfo_flag = false;
    uint8_t *buf;
    switch (type) {
        case NET_TRANSFER_RAM_TO_IOB: // outgoing flow from guest os
           // read packet data from the guest physical memory
            buf = (uint8_t *)malloc(num_bytes);
            panda_physical_memory_rw(src_addr, (uint8_t *)buf, num_bytes, false);

            // Get the IP Header part of this packet
            
            iph = (struct iphdr*)(buf + 14);
            switch (iph->protocol) // Check the Protocol and do accordingly...
            {
                case 1:  // ICMP Protocol
                    break;
                 
                case 2:  // IGMP Protocol
                    break;
                 
                case 6:  // TCP Protocol
                    get_netflow_obj((unsigned char *)buf , num_bytes, nfo);
                    nfo.proto = iph->protocol;
                    nfo_flag = true;
                    break;
                 
                case 17: // UDP Protocol
                    get_netflow_obj((unsigned char *)buf , num_bytes, nfo);
                    nfo.proto = iph->protocol;
                    nfo_flag = true;
                    break;
                 
                default: // Some Other Protocol like ARP etc.
                    break;
            }
            
            if (nfo_flag){ // Taint net flow bytes with the captured netflow object
                for(uint32_t byte_indx = 0; byte_indx < num_bytes; byte_indx++)
                    taint_shadow_netflow(smem, env, src_addr + byte_indx, nfo);
            }
            if (buf)
                free(buf);
            break;
        case NET_TRANSFER_IOB_TO_RAM: // incoming flow from guest os
            // read packet data from the guest physical memory
            buf = (uint8_t *)malloc(num_bytes);
            panda_physical_memory_rw(dest_addr, (uint8_t *)buf, num_bytes, false);
            // Get the IP Header part of this packet
            
            iph = (struct iphdr*)(buf + 14);
            switch (iph->protocol) // Check the Protocol and do accordingly...
            {
                case 1:  // ICMP Protocol
                    break;
                 
                case 2:  // IGMP Protocol
                    break;
                 
                case 6:  // TCP Protocol
                    get_netflow_obj((unsigned char *)buf , num_bytes, nfo);
                    nfo.proto = iph->protocol;
                    nfo_flag = true;
                    break;
                 
                case 17: // UDP Protocol
                    get_netflow_obj((unsigned char *)buf , num_bytes, nfo);
                    nfo.proto = iph->protocol;
                    nfo_flag = true;
                    break;
                 
                default: // Some Other Protocol like ARP etc.
                    break;
            }
            
            if (nfo_flag){ // Taint net flow bytes with the captured netflow object
                for(uint32_t byte_indx = 0; byte_indx < num_bytes; byte_indx++)
                    taint_shadow_netflow(smem, env, dest_addr + byte_indx, nfo);
            }
            if (buf)
                free(buf);
            break;
        case NET_TRANSFER_IOB_TO_IOB:
            break;
        default:
            assert(0);
    }

    return 0;
}


/***** THIS PART HANDLES TAINTING FILE CONTENT *****/

void windows_read_return(CPUState* env, target_ulong pc, uint32_t FileHandle, uint32_t Event, uint32_t UserApcRoutine, uint32_t UserApcContext, uint32_t IoStatusBlock, uint32_t Buffer, uint32_t BufferLength, uint32_t ByteOffset, uint32_t Key) {
    target_ulong pa;
    char *fileName = get_handle_name(env, get_current_proc(env), FileHandle);
    if (!fileName || strlen(fileName) < 2)
       return;
    
    file_obj_t fo;
    std::string fn_str(fileName);
    fo.filename = fileName;
    
    if (file_access.count(fn_str) == 0)
        file_access[fn_str] = 1;
    else
        file_access[fn_str] += 1;
    fo.version = file_access[fn_str];

    for(uint32_t byte_indx = 0; byte_indx < BufferLength; byte_indx++){
        pa = panda_virt_to_phys(env, Buffer + byte_indx);
        if(!taint_shadow_fileobj(smem, env, pa, fo))
            free(fileName);
    }
}

void windows_write_return(CPUState* env,target_ulong pc,uint32_t FileHandle,uint32_t Event,uint32_t ApcRoutine,uint32_t ApcContext,uint32_t IoStatusBlock,uint32_t Buffer,uint32_t Length,uint32_t ByteOffset,uint32_t Key) {

    target_ulong pa;   
    char *fileName = get_handle_name(env, get_current_proc(env), FileHandle);
    if (!fileName || strlen(fileName) < 2)
       return;
    
    file_obj_t fo;
    std::string fn_str(fileName);
    fo.filename = fileName;
    
    if (file_access.count(fn_str) == 0)
        file_access[fn_str] = 1;
    else
        file_access[fn_str] += 1;
    fo.version = file_access[fn_str];
    for(uint32_t byte_indx = 0; byte_indx < Length; byte_indx++){
        pa = panda_virt_to_phys(env, Buffer + byte_indx);
        if(!taint_shadow_fileobj(smem, env, pa, fo))
            free(fileName);
    }
}

/***** THIS PART HANDLES GENERATING OUTPUT FILES *****/

// convert a buffer to a hex string
char out[30000];
std::string to_hex_str_buff(char *buf, uint32_t size) {
    uint32_t i,j;
    out[0] = '\0';
    if(size >= 10000){
        std::string str_null("");
        return str_null;
    }
    for (i = 0,j = 0; i < size; i++, j++)
        sprintf( out + j*2, "%02X", buf[i]);
        
    /*for (i = size - 1,j = 0; i >= 0 ; i--, j++)
        sprintf( out + j*2, "%02X", buf[i]);*/

    out[j*2] = '\0';
    std::string str(out);
    return str;
}
  
// Get current date/time, format is YYYY-MM-DD.HH:mm:ss
const std::string get_current_date_time() {
    time_t     now = time(0);
    struct tm  tstruct;
    char       buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);

    std::string str(buf);
    return buf;
}

// expire taint and clear the syscall and taint structures
void expire_taint(){
    smem.clear();
    final_files.clear();
    final_netflows.clear();
    file_access.clear();
    file_count = 0;
    netflow_count = 0;
    syscalls_info_count = 0;
    cr3_number = 0;
    fileobj_number = 0;
    netflow_number = 0;
    cr3_dic.clear();
    netflow_dic.clear();
    fileobj_dic.clear();
}

void write_file_objects(file_obj_t *fo){

    std::stringstream fo_ss;
    fo_ss << fo->filename << "," << fo->version;
    if (final_files.count(fo_ss.str()) == 0) // store the file object
        final_files[fo_ss.str()] = ++file_count;
    faros_trace << "f" << final_files[fo_ss.str()];
}

// write the taint info into the output file
void write_taint_info(target_ulong addr){

    int c = 0;
    // iterate over the taint info list
    for (auto i: smem[addr]){
        if(c++ != 0)
            faros_trace << ",";
        switch(i.tag_type){
            case CR3:
                faros_trace << cr3_dic[i.tag_index];
                break;
            case NET_FLOW:{
                net_flow_t nfo = netflow_dic[i.tag_index];
                std::stringstream nfo_ss;
                nfo_ss << nfo.src_ip << "," << nfo.src_port << "," << nfo.des_ip << "," << nfo.des_port;
                if (final_netflows.count(nfo_ss.str()) == 0) // store the netFlow object
                    final_netflows[nfo_ss.str()] = ++netflow_count;
                faros_trace << "n" << final_netflows[nfo_ss.str()];	
                }
                break;
            case FILE_OBJ:{
                file_obj_t fo = fileobj_dic[i.tag_index];
                std::stringstream fo_ss;
                fo_ss << fo.filename << "," << fo.version;
                if (final_files.count(fo_ss.str()) == 0) // store the file object
                    final_files[fo_ss.str()] = ++file_count;
                faros_trace << "f" << final_files[fo_ss.str()];
                }
                break;
            
            case MISC:
                faros_trace << i.tag_index;
                break;
            default:
                break;
        }
    } // end for
}
  

// generate all output files
void generate_output_files(){

    uint32_t i,j;
    int str_counter = 0;
    // Generating .cr3 output file
    for ( auto itr = cr3_to_processinfo.begin(); itr != cr3_to_processinfo.end(); ++itr )
        faros_cr3 << "\n" << itr->first << "," << itr->second.pid << "," << itr->second.ppid << "," << itr->second.process_name;
    
    /* Generating machine-readable output file (i.e. .trace file) 
     * according to "syscall info" and "smem" variables
     */
    for (long int index = 0; index < syscalls_info_count; index++){

        faros_trace << syscalls_info[index].timestamp << "," <<syscalls_info[index].syscall_no << "," << syscalls_info[index].cr3 << "," << syscalls_info[index].retval;
        if(syscalls_info[index].fo){
            faros_trace << ",";
            write_file_objects(syscalls_info[index].fo);
        }
	    faros_trace.flush();
	    for (i = 0; i < syscalls_info[index].args_number; i++){
		    if(syscalls_info[index].args[i].size1 == 0)
			    faros_trace << ";";
		    else
			    faros_trace << ";" << to_hex_str_buff((char *)syscalls_info[index].args[i].arg1, syscalls_info[index].args[i].size1);
	        faros_trace.flush();

            target_ulong address;
            uint32_t addr_size;
            if (syscalls_info[index].args[i].pointer_flag == false && syscalls_info[index].args[i].string_flag == false){
                address = syscalls_info[index].args[i].address;
                addr_size = syscalls_info[index].args[i].size1;
            }
            else{
                address = syscalls_info[index].args[i].pointer_value1;
                addr_size = syscalls_info[index].args[i].pointer_size1;
            }
            if (taint_enabled){
                faros_trace << ":";
                for (j = 0; j < addr_size; j++){ // Add taint info
                        target_ulong addr;
                        addr = address + j;
                        // iterate over the taint info list and write the result into the output files
                        write_taint_info(addr);
		                if ( j != addr_size - 1 )
                            faros_trace << "#";
                } // end for
            } // end if
            if(syscalls_info[index].args[i].string_flag == false && syscalls_info[index].args[i].pointer_flag == false){
	            continue;
	        }
	        if (syscalls_info[index].args[i].string_flag == true){ // we have a string argument
                std::string str((char *)syscalls_info[index].args[i].arg2);
                faros_trace << "@" << ++str_counter;
                // write to .string file
                faros_string << str << "\n";
            }
            else{ // we have a buffer argument
		        faros_trace << "&" << to_hex_str_buff((char *)syscalls_info[index].args[i].arg2, syscalls_info[index].args[i].size2);
	        }
	        if (taint_enabled) { // pars taint info
                faros_trace << ":";
	            for (j = 0; j < syscalls_info[index].args[i].pointer_size2; j++){ // Add taint info
		            target_ulong addr = syscalls_info[index].args[i].pointer_value2 + j;
		            // iterate over the taint info list and write the result into the output files
		            write_taint_info(addr);
		            if ( j != syscalls_info[index].args[i].pointer_size2 - 1 )
                           faros_trace << "#";
	            }// end for		
	        }
        }// end for
        faros_trace << "\n";
    }// end for
#ifdef OUTPUT_SMEM
    // generate .smem
    for(auto i: smem){
        if(i.second.size() < 1)
            continue;
        faros_smem << i.first << " -> ";
        for (auto td: i.second){
        
            switch(td.tag_type){
                case CR3:{
                    cr3_t cr3 = cr3_dic[td.tag_index];
                    if (cr3 == 1)
                        faros_smem << "kread;";
                    else if (cr3 == 2)
                        faros_smem << "kwrite;";
                    else if (cr3_to_processinfo.count(cr3) !=0)
                        faros_smem << cr3_to_processinfo[cr3].process_name << ";";
                    else
                        faros_smem << "unknown:" << cr3 << ";";
                    }
                    break;
                case NET_FLOW:{
                    net_flow_t nf = netflow_dic[td.tag_index];
                    faros_smem << "(" << nf.src_ip << ":" << nf.src_port << "," << nf.des_ip << ":" << nf.des_port << ");";
                    }
                    break;
                case FILE_OBJ:{
                    file_obj_t fo = fileobj_dic[td.tag_index];
                    faros_smem << fo.filename << ":" << fo.version << ";";
                    }
                    break;
                case MISC:{
                    misc_t misc = td.tag_index;
                    if (misc == OUTGOING_FLOW_TAG)
                        faros_smem << "OUTGOING_FLOW" << ";";
                    if (misc == INCOMING_FLOW_TAG)
                        faros_smem << "INCOMING_FLOW" << ";";
                    if (misc == EXPORT_TABLE_TAG)
                        faros_smem << "EXPORT_TABLE;";
                    }
                    break;
                 default:
                    break;
             }
        }
        faros_smem << "\n";
    }
    faros_smem.close();  
#endif
    // generate .file output
    for(auto i: final_files)
        faros_file << i.first << "\n";
    // generate .net output
    for(auto i: final_netflows)
        faros_netflow << i.first << "\n";
#ifdef CCS_ENABLED
    // generate .reflective 
    write_potential_injection();
    faros_potential_injection.close();
#endif
    // Close output files
    faros_trace.close();
    faros_cr3.close();
    faros_string.close();
    faros_file.close();
    faros_netflow.close();
    //faros_nettaint.close();

}

// generate all output files when rolling is enabled
int generate_output_files_rolling(){
    std::string date = get_current_date_time();
    fprintf(stdout,"\n creating the output folder...");

    std::string command_mkdir = "mkdir -p ./" + date;
    // create the output folder
    uint32_t ret = system(command_mkdir.c_str());
    if (ret) {
       fprintf(stdout,"\n mkdir failed!");
       return 0;
    }
    // Create output files name
    std::string trace_filename = ".//" + date + "//faros-" + date + ".trace";
    std::string cr3_filename = ".//" + date + "//faros-" + date + ".cr3";
    std::string string_filename = ".//" + date + "//faros-" + date + ".string";
    std::string file_filename = ".//" + date + "//faros-" + date + ".file";
    std::string netflow_filename = ".//" + date + "//faros-" + date + ".net";
    //std::string nettaint_filename = ".//" + date + "//faros-" + date + ".nettaint";
    std::string smem_filename = ".//" + date + "//faros-" + date + ".smem";
#ifdef CCS_ENABLED
    std::string reflective_filename = ".//" + date + "//faros-" + date + ".reflective";
    faros_potential_injection.open(reflective_filename.c_str(), std::ios::out | std::ios::trunc);
#endif
    // Open output files
    faros_trace.open(trace_filename.c_str(), std::ios::out | std::ios::trunc);
    faros_cr3.open(cr3_filename.c_str(), std::ios::out | std::ios::trunc);
    faros_string.open(string_filename.c_str(), std::ios::out | std::ios::trunc);
    faros_file.open(file_filename.c_str(), std::ios::out | std::ios::trunc);
    faros_netflow.open(netflow_filename.c_str(), std::ios::out | std::ios::trunc);
    //faros_nettaint.open(nettaint_filename.c_str(), std::ios::out | std::ios::trunc);
#ifdef OUTPUT_SMEM
    faros_smem.open(smem_filename.c_str(), std::ios::out | std::ios::trunc);
#endif
    // generate the output files
    generate_output_files();
    // expire the taint info
    expire_taint();    
    // move the output folder to ./faros_outputs/ directory
    std::string command_mv = "mv ./" + date + " ./faros_outputs/";
    ret = system(command_mv.c_str());
    if (ret) {
       fprintf(stdout,"\n mv failed!");
       return 0;
    }

    return 1;
}

// A thread to generate output files periodically. It's used when rolling is enabled
void * generate_outputs_thread(void *){

   while (!faros_enabled)
        sleep(1);

   while (1){
        sleep(rolling_time);
        
        pthread_mutex_lock(&thread_lock);
        generate_output_files_rolling();
        pthread_mutex_unlock(&thread_lock);
    }
    return NULL;
}

/***** ThIS PART HANDLES INIT AND UNINIT OF THE PLUGIN *****/

// init the faros plugin
bool init_plugin(void *self) {
    
    // Load required plugins
    panda_require("syscalls2");
    panda_require("win7x86intro");

    // We disable DIFT by default
    taint_enabled = false;
    // We set basic provenance by default
    taint_level = BASIC_TAINT;
    // We disable FAROS at startup by default
    faros_enabled = false;
    // We enable rolling the output files by default
    rolling = true;
    rolling_time = 300; // in seconds
    syscalls_info_count = 0;
    // Parse input arguments, i.e. pid and taint_enable
    panda_arg_list *args = panda_get_args("faros");
    pids.count = 0;
    pnames.count = 0;

    PPP_REG_CB("syscalls2", on_NtReadFile_return, windows_read_return);
    PPP_REG_CB("syscalls2", on_NtWriteFile_return, windows_write_return);
    
    // Allocate memory
    //syscalls_info = (syscall_info *)malloc(MAX_SYSCALL_NO*sizeof(syscall_info));
    syscalls_info = (syscall_info *)calloc(MAX_SYSCALL_NO, sizeof(syscall_info));
    if (!syscalls_info)
       return false;
    if (args != NULL) {
        for (int i = 0; i < args->nargs; i++) {
            //faros_log << "\n key: " << strncmp(args->list[i].key;
            if (0 == strncmp(args->list[i].key, "pid", 3)) {
                std::string pid_list(args->list[i].value);
                std::string delimiter = "-";
                size_t pos = 0;
                std::string pid;
                while ((pos = pid_list.find(delimiter)) != std::string::npos) {
                    pid = pid_list.substr(0, pos);
                    pids.pid[pids.count] = atoi(pid.c_str());
                    pids.count++;
                    pid_list.erase(0, pos + delimiter.length());
                }
                pids.pid[pids.count] = atoi(pid_list.c_str());
                pids.count++;
            }
            else if (0 == strncmp(args->list[i].key, "pname", 5)) {
                std::string pname_list(args->list[i].value);
                std::string delimiter = "-";
                size_t pos = 0;
                std::string pname;
                while ((pos = pname_list.find(delimiter)) != std::string::npos) {
                    pname = pname_list.substr(0, pos);
                    pnames.pname[pnames.count] = std::string(pname.c_str(), strlen(pname.c_str()));
                    pnames.count++;
                    pname_list.erase(0, pos + delimiter.length());
                }
                pnames.pname[pnames.count] = std::string(pname_list.c_str(), strlen(pname_list.c_str()));
                pnames.count++;
            }
            else if (0 == strncmp(args->list[i].key, "taint_enable", 12)) {
                if (0 == strncmp(args->list[i].value, "on", 2))
                    taint_enabled = true;
            }
            else if (0 == strncmp(args->list[i].key, "rolling_time", 12)) {
                rolling_time = atoi(args->list[i].value);
            }
            else if (0 == strncmp(args->list[i].key, "taint_level", 11)) {
                if (0 == strncmp(args->list[i].value, "basic", 5)) {
                    taint_enabled = true;
                    taint_level = BASIC_TAINT;
                }
                else if (0 == strncmp(args->list[i].value, "full", 4)) {
                    taint_enabled = true;
                    taint_level = FULL_TAINT;
                }
                else {
                    fprintf(stderr, "\nPlugin 'faros' needs arguments: -panda faros:pid=pid-pid-...-pid,start_immediately=on/off,taint_enable=on/off,taint_level=basic/full,rolling=on/      off,rolling_time=<time in second>\n");
                    fprintf(stderr, "\tExample: -panda faros:pid=1726-2345,taint_enable=true,taint_level=full,rolling_time=3600\n");
                    return false;
                }
            }
            else if (0 == strncmp(args->list[i].key, "start_immediately", 17)) {
                if (0 == strncmp(args->list[i].value, "on", 2)){
                    faros_enabled = true;
                    fprintf(stdout, "\nEnabling FAROS");
                }
            }
            else if (0 == strncmp(args->list[i].key, "rolling", 7)) {
                if (0 == strncmp(args->list[i].value, "off", 3))
                    rolling = false;
            }
            else{
                    fprintf(stderr, "\nPlugin 'faros' needs arguments: -panda faros:pid=pid-pid-...-pid,start_immediately=on/off,taint_enable=on/off,taint_level=basic/full,rolling=on/off,rolling_time=<time in second>\n");
                 fprintf(stderr, "\tExample: -panda faros:pid=1726-2345,taint_enable=true,taint_level=full,rolling_time=3600\n");
                 return false;
            }
        }
    }

    // Open faros output files
    faros_log.open("faros.log", std::ios::out | std::ios::trunc);
    if (rolling == false) {
        faros_trace.open("faros.trace", std::ios::out | std::ios::trunc);
        faros_cr3.open("faros.cr3", std::ios::out | std::ios::trunc);
        faros_string.open("faros.string", std::ios::out | std::ios::trunc);
        faros_file.open("faros.file", std::ios::out | std::ios::trunc);
        faros_netflow.open("faros.net", std::ios::out | std::ios::trunc);
        //faros_nettaint.open("faros.nettaint", std::ios::out | std::ios::trunc);
#ifdef OUTPUT_SMEM
        faros_smem.open("faros.smem", std::ios::out | std::ios::trunc);
#endif
#ifdef CCS_ENABLED
        faros_potential_injection.open("faros.injection", std::ios::out | std::ios::trunc);
#endif
    }
    else {
        pthread_mutex_init(&thread_lock, NULL);
        pthread_create (&write_thread, NULL, generate_outputs_thread, NULL);
    }

    panda_cb pcb;
    pcb.monitor = monitor_callback;
    panda_register_callback(self, PANDA_CB_MONITOR, pcb);

    //pcb.faros_net_recv = faros_net_recv;
    //panda_register_callback(self, PANDA_CB_FAROS_NET_RECV, pcb);
    if (taint_enabled){

        // Load/propagate when we dma from the network card (e1000 only!)
        //pcb.faros_net_recv = faros_net_recv;
        //panda_register_callback(self, PANDA_CB_FAROS_NET_RECV, pcb);      
        // TODO
        //pcb.faros_net_send = faros_net_send;
        //panda_register_callback(self, PANDA_CB_FAROS_NET_SEND, pcb);

        if (taint_level == FULL_TAINT) {
            // This callback is where the actual propagation happens
            pcb.after_block_exec = after_block_exec;
            panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);

#ifdef CCS_ENABLED
            pcb.before_block_exec = before_block_exec;
            panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
            tag_kernel = true;
#endif
            
            // Load/propagate when accessing physical memory
            pcb.phys_mem_read = phys_read_callback;
            panda_register_callback(self, PANDA_CB_PHYS_MEM_READ, pcb);
            pcb.phys_mem_write = phys_write_callback;
            panda_register_callback(self, PANDA_CB_PHYS_MEM_WRITE, pcb);

            // Enable memory callbacks (for mem_read and mem_write)
            panda_enable_memcb();
            panda_do_flush_tb();        
            panda_disable_tb_chaining();
            panda_enable_precise_pc(); // required for asid

        }
    }

    // This callback is where a system call returns
    PPP_REG_CB("syscalls2", on_all_sys_return, all_syscall_return);
    
    pcb.replay_net_transfer = cb_replay_net_transfer;
    panda_register_callback(self, PANDA_CB_REPLAY_NET_TRANSFER, pcb);
    
    //pcb.replay_handle_packet = handle_packet;
    //panda_register_callback(self, PANDA_CB_REPLAY_HANDLE_PACKET, pcb); 
    

    // init osi plugin
    if(!init_osi_api())
        return false;
    faros_log << "\nFaros loading ...!";
    std::cout << "\nFaros Started. Nothing to see here. Move along!\n";

    return true;
}


// uninit the faros plugin
void uninit_plugin(void *self) {

	faros_log << "\nFaros unloading...\n";
	// check to see if rolling the output files is enabled
    if (rolling == true){
        generate_output_files_rolling();
        pthread_mutex_destroy(&thread_lock);
    }
    else        
        generate_output_files(); // generate the output files
    faros_log.close();
}

#endif
