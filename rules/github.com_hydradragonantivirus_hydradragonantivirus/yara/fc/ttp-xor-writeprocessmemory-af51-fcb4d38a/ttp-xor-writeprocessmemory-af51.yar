rule TTP_XOR_WriteProcessMemory_af51 {
  strings:
    $key_af51 = { f8 23 [2] ca 01 [2] cc 34 [2] e2 34 [2] dd 28 }

  condition:
    any of them
}