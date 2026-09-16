rule TTP_XOR_WriteProcessMemory_c750 {
  strings:
    $key_c750 = { 90 22 [2] a2 00 [2] a4 35 [2] 8a 35 [2] b5 29 }

  condition:
    any of them
}