rule TTP_XOR_WriteProcessMemory_bc69 {
  strings:
    $key_bc69 = { eb 1b [2] d9 39 [2] df 0c [2] f1 0c [2] ce 10 }

  condition:
    any of them
}