rule TTP_XOR_WriteProcessMemory_65b0 {
  strings:
    $key_65b0 = { 32 c2 [2] 00 e0 [2] 06 d5 [2] 28 d5 [2] 17 c9 }

  condition:
    any of them
}