
# Introduction

This folder provides a basic GP callback model for the SGX enclave code.

# Unsupported feature

- TEEC_SharedMemory not supported (only support TEEC_TempMemoryReference)


# Working flow

- Load Enclave so file:
  - The so file must be in a fixed file name

- Load 