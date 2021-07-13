# hAFL1
## About The Project
TBC with a link to our [BlackHat talk](https://www.blackhat.com/us-21/briefings/schedule/#hafl-our-journey-of-fuzzing-hyper-v-and-discovering-a--day-23498) :)

## Deployment Guide
__Disclaimer__: We used hAFL1 to fuzz Hyper-V’s virtual switch (_vmswitch.sys_). The fuzzer can be adjusted to fuzz other target drivers, but this tutorial will focus on fuzzing the above-mentioned driver.

### Install kAFL
This phase will build Linux, kvm and hAFL1 (a modified kAFL) on your Linux machine.

__Note__: make sure you run the fuzzer on a machine with a CPU that supports Intel-PT.

1. Clone this repository.

2. Enter the kAFL directory.

3. Run `install.sh all`

### Compile Necessary Binaries
You need to compile both the harness and fuzzing binaries from the kAFL codebase. We will be using two of them - _packet_sender.exe_ (the program which triggers the packet-sending IOCTL) and _loader.exe_ (which loads and executes _packet_sender.exe_).

1. Compile hAFL1’s fuzzing binaries by executing `./hAFL1/targets/windows_86_64/compile.sh`.

2. Use Visual Studio to compile both:

   * The harness driver (_Harness.{sys,inf,cer,cat}_)
   * _StructsInitiator.exe_

### Creating a VM
__Note__: During the installation, whenever Windows tries to restart, QEMU might hang with a black screen. If that is the case, quit QEMU (`Ctrl+C`) and re-run the VM.

#### Deploy a Windows 10 VM
1. Obtain a Windows 10 [ISO file](https://techbench.luzea.ovh/download.html?id=2004). We’ll be using `Windows10_InsiderPreview_Client_x64_en-us_21354.iso`.

2. Create a QEMU disk image by running 

   ```./hAFL1/qemu-5.0.0/qemu-img create -f qcow2 windows.qcow2 50G```.

3. Download [_OVMF_CODE-pure-efi.fd_](https://github.com/SB-GC-Labs/hAFL1/blob/main/OVMF_CODE-pure-efi.fd).

4. Boot the machine:
   ```
   ./hAFL1/qemu-5.0.0/x86_64-softmmu/qemu-system-x86_64 -cpu host,hv_relaxed,hv_spinlocks=0x1fff,hv_vapic,hv_time,+intel-pt,-hypervisor,+vmx -machine q35 -enable-kvm -m 6144 -hda   ./windows.qcow2 -bios /root/kAFL-1/OVMF_CODE-pure-efi.fd -cdrom ./Windows10_InsiderPreview_Client_x64_en-us_21354.iso -net none -usbdevice tablet
   ```

5. Install Windows Pro, which has Hyper-V capabilities, and complete the installation process.

6. Consider disabling Windows Defender permanently.

7. Disable memory dump collection during crashes, by running the following PowerShell command as Administrator:
   ```
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 0
   ```

8. Enable Hyper-V on the VM by running the following within a PowerShell console as Administrator: 
   
   ```Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All```
9. Create an empty VM by using PowerShell console as Administrator:
   
   ```New-VM -Name "VM" -MemoryStartupBytes 512MB```

#### Prepare the Machine for Fuzzing
1. Enable Driver Verifier for vmswitch.sys:

   ```verifier /standard /driver vmswitch.sys```

2. Turn off the VM.

3. Group the following files in a dedicated folder (files in bold should be compiled in previous steps):

   * Devcon.exe ([Debugging Tools for Windows](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/)) - this will install the harness driver
   * __Harness.sys__, __Harness.inf__, __Harness.cat__, __Harness.cer__ (Harness folder in hAFL1 Repo) - these files comprise the harness driver
   * __loader.exe__ (`./hAFL1/targets/windows_86_64/bin/loader/loader.exe`) - this is a kAFL-provided binary which loads
   * __StructsInitiator.exe__ - This will prepare all necessary structures in vmswitch for the fuzzing process
   * VMSwitchInitBuffer.bin - this is a file required by StructsInitiator.exe
   * EfiDSEFix.exe (Download [here](https://github.com/Mattiwatti/EfiGuard/releases/download/v1.2.1/EfiGuard-v1.2.1.zip))

4. Copy the files from the dedicated folder to the VM by running:
   
   ```./hAFL1/copy_files_to_vm.sh <dedicated_folder_path> windows.qcow2```
   
   The files will be copied to the `C:\` hard drive.

#### Create an Overlay

1. Create an overlay in a dedicated folder of overlays:

   ```./hAFL1/qemu-5.0.0/qemu-img create -f qcow2 -b windows.qcow2 overlay_0.qcow2```

#### Disable PatchGuard and Driver Signature Enforcement

1. Download [EFIGuardBootable.iso](https://github.com/SB-GC-Labs/hAFL1/blob/main/EFIGuardBootable.iso) and save it to the hAFL1 folder:

2. Execute the overlay VM:
   ```
   ./hAFL1/qemu-5.0.0/x86_64-softmmu/qemu-system-x86_64 -enable-kvm -cpu host,hv_relaxed,hv_spinlocks=0x1fff,hv_vapic,hv_time,+intel-pt,-hypervisor,-vmx -usbdevice tablet -m 6144 -bios /root/hAFL1/OVMF_CODE-pure-efi.fd -drive file=overlay_0.qcow2 -machine q35 -cdrom /root/hAFL1/EFIGuardBootable.iso boot menu=on
   ```
   
3. Boot to EFI Shell by pressing ESC once the “TianoCore” logo appears.

4. Enter “Boot Manager” and choose “EFI Internal Shell”

5. Execute the following command:
```load FS1:\EFI\Boot\EfiGuardDxe.efi```

6. You should see “Success” printed at the bottom of the screen.

7. Type `exit` and hit enter to exit the shell.

8. Choose `Windows Boot Manager` and Windows will be loaded without _PatchGuard_.

9. Open cmd.exe and execute `C:\EfiDSEFix.exe -d`

#### Create a Snapshot

1. Install harness driver by using devcon.exe:
   ```
   devcon.exe install Harness.inf root\Harness
   ```
   Approve the popup message.

2. Extract the new VM’s GUID and its network adapter’s GUID by running the following commands within PowerShell:
   ```
   (Get-VMNetworkAdapter VM)[0].id
   ```
   
	 The output contains: `Microsoft:<VM_GUID>\<NETWORK_ADAPTER_GUID>`.

3. Execute StructsInitiator.exe:
   
   ```
   StructsInitiator.exe <VM_GUID> <ADAPTER_GUID> <VM_NAME> VMSwitchInitBuffer.bin
   ```

4. Execute loader.exe. This will create a snapshot to which the fuzzer will return after crashes.

### Duplicating VM overlays (Optional)
If you’d like to run multiple VM instances to increase the performance of the fuzzing process, duplicate the overlay_0.qcow2 file by executing the following command. Replace `X` with the number of instances you’d like to create in addition to the original `overlay_0` file.
```
for f in overlay_{1..X}.qcow2; do cp overlay_0.qcow2 $f; done
```

### Start Fuzzing

1. Run the following command and fetch from its output the address of vmswitch in memory:
```
python3 kAFL-Fuzzer/kafl_info.py -work_dir work -vm_dir <OVERLAY_DIR> -bios OVMF_CODE-pure-efi.fd -mem 6144 -agent targets/windows_x86_64/bin/info/info.exe -v
```

2. Run the following command in order to start with the fuzzing process in debug mode. Replace `<start_address>` and `<end_address>` with the output from the previous step.
```
python3 kAFL-Fuzzer/kafl_fuzz.py -work_dir work --purge -vm_dir <OVERLAY_DIR> -bios OVMF_CODE-pure-efi.fd -mem 6144 -agent targets/windows_x86_64/bin/fuzzer/packet_sender.exe -seed_dir <SEED_DIR> -p <NUMBER_OF_INSTANCES>-ip0 <start_address>-<end_address> --debug -v
```

3. You can run the fuzzer’s GUI by executing in a separate terminal (or tmux pane):
```
python3 kAFL-Fuzzer/kafl_gui.py work
```

4. Once you verify that everything works properly, you may omit the `-v` and `--debug` flags to save some space on the disk (and not write all of the logs.)

### Analyze Coverage and Crashes
See [this guide](https://github.com/SB-GC-Labs/hAFL1/blob/main/coverage_analysis.md).


### Integrating LPBM
`<TODO>`

