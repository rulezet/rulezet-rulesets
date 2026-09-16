rule TTP_XOR_WriteProcessMemory_77c0 {
  strings:
    $key_77c0 = { 20 b2 [2] 12 90 [2] 14 a5 [2] 3a a5 [2] 05 b9 }

  condition:
    any of them
}