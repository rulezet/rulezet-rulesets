rule TTP_XOR_WriteProcessMemory_af6c {
  strings:
    $key_af6c = { f8 1e [2] ca 3c [2] cc 09 [2] e2 09 [2] dd 15 }

  condition:
    any of them
}