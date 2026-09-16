rule TTP_XOR_WriteProcessMemory_af76 {
  strings:
    $key_af76 = { f8 04 [2] ca 26 [2] cc 13 [2] e2 13 [2] dd 0f }

  condition:
    any of them
}