rule TTP_XOR_WriteProcessMemory_af0c {
  strings:
    $key_af0c = { f8 7e [2] ca 5c [2] cc 69 [2] e2 69 [2] dd 75 }

  condition:
    any of them
}