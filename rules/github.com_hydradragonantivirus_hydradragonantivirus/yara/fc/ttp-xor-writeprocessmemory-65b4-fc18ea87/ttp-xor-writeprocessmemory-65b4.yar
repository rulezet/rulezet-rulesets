rule TTP_XOR_WriteProcessMemory_65b4 {
  strings:
    $key_65b4 = { 32 c6 [2] 00 e4 [2] 06 d1 [2] 28 d1 [2] 17 cd }

  condition:
    any of them
}