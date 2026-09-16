rule TTP_XOR_WriteProcessMemory_af71 {
  strings:
    $key_af71 = { f8 03 [2] ca 21 [2] cc 14 [2] e2 14 [2] dd 08 }

  condition:
    any of them
}