rule TTP_XOR_WriteProcessMemory_af7e {
  strings:
    $key_af7e = { f8 0c [2] ca 2e [2] cc 1b [2] e2 1b [2] dd 07 }

  condition:
    any of them
}