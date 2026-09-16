rule TTP_XOR_WriteProcessMemory_65d1 {
  strings:
    $key_65d1 = { 32 a3 [2] 00 81 [2] 06 b4 [2] 28 b4 [2] 17 a8 }

  condition:
    any of them
}