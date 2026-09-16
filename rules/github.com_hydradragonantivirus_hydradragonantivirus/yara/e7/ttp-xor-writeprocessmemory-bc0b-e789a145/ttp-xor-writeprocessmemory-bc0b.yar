rule TTP_XOR_WriteProcessMemory_bc0b {
  strings:
    $key_bc0b = { eb 79 [2] d9 5b [2] df 6e [2] f1 6e [2] ce 72 }

  condition:
    any of them
}