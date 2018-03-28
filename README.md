## FAROS PANDA COMPONENT

FAROS is a full-system dynamic information flow tracking system designed to
provide provenance information about tagged bytes of memory and to try and
use more complex tags/types to handle address and control dependencies properly.

To try and have FAROS operate on a live system, we've built our code on the top of 
the `PANDA` system, with a few modifications to enable access to network traffic
without needing to be in replay mode. FAROS is based off PANDA commit 
5606090f575a25e4de83af4e3c6a7f6f70050bf7. All modified code should have a 
comment with the text, FAROS before it, along with the initials of the person
who made the modification.

## INSTALL

To install the PANDA component of FAROS, install all the required libraries
to install PANDA as detailed in [README_PANDA.md](README_PANDA.md). 

Once you have installed all the dependencies run the install script, found at
[qemu/build.sh](qemu/build.sh).


## FAROS PLUGIN

FAROS's DIFT system has been created as a plugin to PANDA which captures all system calls with their arguments 
and provides provenance information for every byte of each argument. It uses:

* A few of the callbacks which we've added to PANDA, to allow the live-system network traffic to tag/taint. 

* A heavily modified version of syscalls2 plugin to capture all system calls with their arguments.
    
* win7x86intro and osi plugins to get process info associated with each system call.
    
This plugin can be found in the panda_plugins directory under the folder, faros.


## RUNNING FAROS

We can run FAROS in two modes: 1. Real time 2. Record/Replay. We recommand using FAROS in Record/Replay mode for now.

### I. Real time

In this mode, we run FAROS plugin at the same time we run our VM.

    1.1 $cd qemu/
    1.2 $sudo ./i386-softmmu/qemu-system-i386 -hda PATH_TO_VM_IMG/win7.qcow -m 4048 --monitor stdio -netdev user,id=net0 -device e1000,netdev=net0 -panda faros -vnc :1
    1.3 After Windows comes up fully you need to enable FAROS:
        (qemu) plugin_cmd faros_enable
    1.4 At any point we can disable FAROS
        (qemu) plugin_cmd faros_disable
    1.5 At any point we can enable FAROS again
        (qemu) plugin_cmd faros_enable
    1.6 Exit QEMU
        (qemu) quit


### II. Record/Replay

In this mode, we first record PANDA traces without a previously loaded plugin, and then replay that with the loaded plugins.
    
    2.1 Record
        2.1.1 Start VM:
            $cd qemu/
            $sudo ./i386-softmmu/qemu-system-i386 -hda PATH_TO_VM_IMG/win7.qcow -m 4000 --monitor stdio -netdev user,id=net0 -device e1000,netdev=net0 -vnc :1
        2.1.2 Start recording
            (qemu) begin_record record_name
        2.1.3 Stop recording
            (qemu) stop_record
        2.1.4 Exit QEMU
            (qemu) quit
    2.2 Replay
        2.2.1 Start VM
            $cd qemu/
            $sudo ./i386-softmmu/qemu-system-i386 -replay record_name -m 4048 --monitor stdio -netdev user,id=net0 -device e1000,netdev=net0 -panda faros:start_immediately=on

### Command line options

FAROS plugin provides several input arguments:

**1. pid**
              
    If you need to filter out the outputs according to some processes, you only need to initiate *pid* argument in the command line by a list of PIDs, separated by "-". This option is set to capture the syscalls for all processes by default. For example, the following command

        $sudo ./i386-softmmu/qemu-system-i386 -replay record_name -m 4048 --monitor stdio -netdev user,id=net0 -device e1000,netdev=net0 -panda faros:start_immediately=on,pid=1234-1244

    filters out the result for processes with pid=1234 and pid=1244.

**2. taint_enable**
    
    Taint engine has been disabled by default. If you need to enable taint engine, you only need to initiate *taint_enable* argument in the command line by "on". For example, the following command

        $sudo ./i386-softmmu/qemu-system-i386 -replay record_name -m 4048 --monitor stdio -netdev user,id=net0 -device e1000,netdev=net0 -panda faros:start_immediately=on,pid=1234-1244,taint_enable=on
        
    enables taint engine and filters out the result for processes with pid=1234 and pid=1244.

**3. taint_level**
    
    FAROS offers to level of tainting: basic and full. It's set to *basic* by default.
    
        -panda faros:taint_level=full
    
**4. rolling**
    
    Rolling log files is enabled by default. To disable rolling log files you need to initiate *rolling* argument by "off".
    
        -panda faros:rolling=off
    
**5. rolling_time**
    
    It indicates the time period for rolling log files. It's set to 3600 seconds by default. To set it to a diiferent value:
    
        -panda faros:rolling_time=200
    
**6. start_immediately**
    
    It indicates it FAROS should start working immediately or not. It's set to "off" by default. This option is basically used for replay so as to FAROS can start working immediately. To turn it on:
    
        -panda faros:start_immediately=on
            

**Note:** Each of the above options can be used together separated by comma. Here is an example:

        -panda faros:start_immediately=on,rolling=off,pid=1724

We usaully use this combination when we wants to replay a recording.


## FAROS OUTPUTS

FAROS plugin generates three outputs under the following directory:

        PATH_TO_FAROS_DIR/faros-faros_panda/panda/qemu/
 
These three outputs are as follows:
 
        1. faros.trace
           Machine-readable output.
           
        2. faros.string
           List of all strings captured as a system call argument.
           
        3. faros.cr3
           List of CR3 values with their corresponding PID, PPID and process name.

Then we can translate these outputs into human-readable and CDM outputs using [translator](../translator).

### .trace file format

In each line we have the following format: (each line corresponds to one system call)

     timestamp,syscall_no,cr3,return_value;arg0:taint_info;arg1:taint_info;.....;argn:taint_info 

We can represent this format in the following table:

General system call info              | Arg 0 info      | Arg 1 info      | ... | Arg n info      |
------------------------------------  | --------------- | --------------- | --- | --------------- |
timestamp,syscall_no,cr3,return_value | arg0:taint_info | argn:taint_info | ... | argn:taint_info |

General syscall info includes:

* Unix timestamp
* System call number
* CR3 value
* Return value

Arg info includes:

* Argument value (in hex)
* Taint/Provenance information

Taint info contains a CR3 list for each byte separated by #. Here is an example of taint_info for a 4-byte argument:

    2366791680,2366791681#2366791680,2366791681#2366791680#2366791680

**Note 1:** If an argument value is a string, we assign an index number (corresponding to the line number in .string file) to that string, and put that number for argument value in .trace file.

**Note 2:** If an argument has a sub-argument (dereferenced argument) and this sub-argument is a string, we separate it by @. So the format for this argument will be as follows:

        ;arg0:taint_info@arg01:taint_info;

arg01, i.e. the sub-argument, is a number which is the line number in .string file.

**Note 3:** If an argument has a sub-argument (dereferenced argument) and this sub-argument is a buffer, we separate it by &. So the format for this argument will be as follows:

        ;arg0:taint_info&arg01:taint_info;

arg01, i.e. the sub-argument, is hex representation of the buffer.

### .cr3 file format

Each line in this file corresponds to one CR3 value and its corresponding PID, PPID, and process name:

    CR3 value,PID,PPID,Process name

### .string file format

Each line of this file is a string captured as a system call argument.

## License

GPLv2

