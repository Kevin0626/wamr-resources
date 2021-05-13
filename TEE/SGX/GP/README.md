
# Introduction

This folder provides a basic GP callback model for the SGX enclave code.

# Unsupported feature

- TEEC_SharedMemory not supported (only support TEEC_TempMemoryReference)


# Working flow

- Load Enclave so file:
  - The so file must be in a fixed file name

- Load 

# Set up
1. Download __sgx_platform_x64_sdk_ver.bin__ from [Intel® Software Guard Extensions](https://software.intel.com/content/www/us/en/develop/topics/software-guard-extensions/sdk.html)
2. Install the sgx-sdk under directory __/opt/intel__
3. Execution following command
```shell
    cd TEE/SGX/GP;
    make;
    ./hello_world
```