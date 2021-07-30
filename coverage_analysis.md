# Print Unique Crashes
Use the `./hAFL1/tools/print_uniq_crashes.py` script.  

# kAFL to Lighthouse (Coverage Converter)

The following `README` explains how to:
1. Generate `kAFL` Trace files
2. Convert it to a [`Lighthouse`](https://github.com/gaasedelen/lighthouse) compatible format (in order to visualize the coverage)

---
## Generate kAFL Trace Files + Convert it to Lighthouse Compatible Format
* kAFL doesn't generate trace files by default, it does it on-demand.
* The `kafl_cov.py` script is working on a different work folder, and doesn't interrupt the main fuzzer.
### Prerequisites
1. Duplicate `overlay_0.qcow2` and rename the duplicated file to `overlay_1337.qcow2`
2. Install Lighthouse on IDA
### Explanation
1. When kAFL generates a payload which has changed the coverage, it saves it to the following folder:  
```[kAFL_work_folder]\corpus\[execution_result]\payload_[XXXXX]```  
execution_result can be one of the following: `regular, crash, kasan, timeout`  

2. The `kafl_cov.py` script scans the `[kAFL_work_folder]\corpus` folder, spawns a QEMU debug instance (```overlay_1337.qcow2```) and sends the payloads to the agent which is executed within the VM.

3. Each time the `kafl_cov.py` sends a payload, it sends the ENABLE_TRACE_MODE hypercall to the VM, which causes QEMU-PT to dump basic blocks transitions (by Intel PT) to `redqueen_workdir\pt_trace_results.txt`

4. After the payload is done executed, the script copies the content of `pt_trace_results.txt` file (compressed as LZ4) to `[kAFL_work_folder]\traces\payload_XXXXX.lz4`

5. Next, The `unique_edges.sh` script must be used in order to merge all of the trace files into a single file which contains the addresses of the unique edges: `[kAFL_work_folder]\edges_uniq.lst`

6. Last but not least, the Unique Edges file must be converted to Lighthouse compatible format by using our own script [`convert_kAFL_coverage_to_lighthouse.py`](https://github.com/SB-GC-Labs/hAFL1/blob/main/tools/convert_kAFL_coverage_to_lighthouse.py).

---
## How To (Step-By-Step)
0. Make sure you have an overlay file named `overlay_1337.qcow2` which is identical to the original overlay files which you used during the original fuzzing.
1. **Make sure you are using a different work folder, use the original work folder only as the `-input` parameter!**  
    Run the following command in order to generate trace files:  
    ```
    python3 kAFL-Fuzzer/kafl_cov.py -work_dir [NEW_WORK_DIR] -v -input [ORIGINAL_WORK_DIR]  -bios /usr/share/edk2.git/ovmf-x64/OVMF_CODE-pure-efi.fd -agent targets/windows_x86_64/bin/fuzzer/vuln_test.exe -mem 6144 -ip0 [DRIVER_ADDR_RANGE]

    ```
2. Next, run the following in order to merge all edges into a single file:  
   ```
   tools/uniq_edges.sh [ORIGINAL_WORK_DIR]
   ```
3. Copy the edges_uniq.lst file from the original work directory.
4. Convert it to a Lighthouse compatible format as following:
    ```
    python convert_kAFL_coverage_to_lighthouse.py [uniq_edges_folder_path] [output_file_path]
    ```
5. Open IDA and Rebase the target driver to the base address you used with `kAFL_cov.py`
6. Make sure IDA rebased the module properly (sometime it needs to be done twice!)
7. Load the converted output file within the IDA GUI (Make sure you installed Lighthouse):
   ```
    File -> Load File -> Code Coverage File
   ```
