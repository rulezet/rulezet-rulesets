rule TTP_XOR_WriteProcessMemory_af09 {
  strings:
    $key_af09 = { f8 7b [2] ca 59 [2] cc 6c [2] e2 6c [2] dd 70 }

  condition:
    any of them
}