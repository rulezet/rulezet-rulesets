rule TTP_XOR_WriteProcessMemory_af5b {
  strings:
    $key_af5b = { f8 29 [2] ca 0b [2] cc 3e [2] e2 3e [2] dd 22 }

  condition:
    any of them
}