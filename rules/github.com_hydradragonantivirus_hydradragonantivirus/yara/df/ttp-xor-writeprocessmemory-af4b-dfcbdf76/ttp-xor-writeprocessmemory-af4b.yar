rule TTP_XOR_WriteProcessMemory_af4b {
  strings:
    $key_af4b = { f8 39 [2] ca 1b [2] cc 2e [2] e2 2e [2] dd 32 }

  condition:
    any of them
}