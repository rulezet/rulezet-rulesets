rule TTP_XOR_WriteProcessMemory_af7c {
  strings:
    $key_af7c = { f8 0e [2] ca 2c [2] cc 19 [2] e2 19 [2] dd 05 }

  condition:
    any of them
}