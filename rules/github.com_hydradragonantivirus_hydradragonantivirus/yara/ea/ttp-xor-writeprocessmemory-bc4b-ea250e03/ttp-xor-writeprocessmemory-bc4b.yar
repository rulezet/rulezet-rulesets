rule TTP_XOR_WriteProcessMemory_bc4b {
  strings:
    $key_bc4b = { eb 39 [2] d9 1b [2] df 2e [2] f1 2e [2] ce 32 }

  condition:
    any of them
}