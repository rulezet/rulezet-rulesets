rule TTP_XOR_WriteProcessMemory_af4e {
  strings:
    $key_af4e = { f8 3c [2] ca 1e [2] cc 2b [2] e2 2b [2] dd 37 }

  condition:
    any of them
}