rule TTP_XOR_WriteProcessMemory_bc9e {
  strings:
    $key_bc9e = { eb ec [2] d9 ce [2] df fb [2] f1 fb [2] ce e7 }

  condition:
    any of them
}