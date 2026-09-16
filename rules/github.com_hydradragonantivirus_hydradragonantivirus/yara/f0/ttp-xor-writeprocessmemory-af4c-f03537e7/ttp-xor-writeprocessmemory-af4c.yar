rule TTP_XOR_WriteProcessMemory_af4c {
  strings:
    $key_af4c = { f8 3e [2] ca 1c [2] cc 29 [2] e2 29 [2] dd 35 }

  condition:
    any of them
}