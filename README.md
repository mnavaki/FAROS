## FAROS

FAROS (means lighthouse in greek) is a reverse engineering tool
for Windows malware analysis based on dynamic information
flow tracking (DIFT), which can flag stealthy in-memory-only
malware injection attacks, e.g. reflective DLL injection. FAROS is developed as a plugin for PANDA dynamic analysis framework.

The key novelty of FAROS is the synergy of: (i) whole-system DIFT; (ii) per security-policy-
based strategy to overcome the challenge of handling indirect
flows via the application of tags with different types and
using their unique confluence on a memory location as attack
invariant, and (iii) the use of tags with fine-grained provenance
information.

## Install

To install the PANDA component of FAROS, install all the required libraries
to install PANDA as detailed in [README_PANDA.md](README_PANDA.md). 

Once you have installed all the dependencies run the install script, found at
[qemu/build.sh](qemu/build.sh).


## FAROS Plugin

This plugin can be found in the panda_plugins directory under the folder, faros.


## Running FAROS

FAROS can be run in two modes: 1. Real time 2. Record/Replay, but we only recommand using FAROS in Record/Replay mode.

### How To Run

To use FAROS, an analyst needs to set up a Windows
7 VM, start PANDA recording mode (to enable instruction
emulation), and then run the malware he wants to analyze
along with any other applications or activities that he is
interested in observing inside the VM. Once the interesting
activities are completed, the analyst stops the recording mode
and initiates the PANDA replay of the recorded capture
with the FAROS plugin loaded and performing taint analysis.
FAROS will generate an output file indicating whether there
are any potential in-memory injection attacks. If such an attack
has been captured, the FAROS plugin provides the memory
addresses of the instructions that were captured as part of
the malicious injected payload, along with the provenance
list associated with each one of these memory addresses.

   
    1 Record
        1.1 Start VM:
            $cd qemu/
            $sudo ./i386-softmmu/qemu-system-i386 -hda PATH_TO_VM_IMG/win7.qcow -m 1G --monitor stdio -netdev user,id=net0 -device e1000,netdev=net0 -vnc :1
        1.2 Start recording
            (qemu) begin_record record_name
        1.3 Stop recording
            (qemu) stop_record
        1.4 Exit QEMU
            (qemu) quit
    2 Replay
        2.1 Start VM
            $cd qemu/
            $sudo ./i386-softmmu/qemu-system-i386 -replay record_name -m 1G --monitor stdio -netdev user,id=net0 -device e1000,netdev=net0 -panda faros:pname=mal.exe


## FAROS Output

FAROS plugin generates an output file (i.e. faros.taint) under the following directory:

        PATH_TO_FAROS_DIR/faros-faros_panda/panda/qemu/
 
This file containts all information of detected in-memory injection attacks.

## Publications

----
* Meisam Navaki Arefi, Geoffrey Alexander, Hooman Rokham, Aokun Chen, Daniela Oliveira, Xuetao Wei, Michalis Faloutsos, and Jedidiah R. Crandall. **FAROS: Illuminating In-Memory Injection Attacks via Provenance-based Whole System Dynamic Information Flow Tracking**. Accepted (pending shepherd approval) to the IEEE/IFIP International Conference on Dependable Systems and Networks (DSN 2018). Luxembourg City, Luxembourg. June 2018.

## License

GPLv2

