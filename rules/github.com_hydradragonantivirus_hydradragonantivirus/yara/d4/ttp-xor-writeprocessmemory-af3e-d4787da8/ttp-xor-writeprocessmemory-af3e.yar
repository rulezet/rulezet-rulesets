rule TTP_XOR_WriteProcessMemory_af3e {
  strings:
    $key_af3e = { f8 4c [2] ca 6e [2] cc 5b [2] e2 5b [2] dd 47 }

  condition:
    any of them
}