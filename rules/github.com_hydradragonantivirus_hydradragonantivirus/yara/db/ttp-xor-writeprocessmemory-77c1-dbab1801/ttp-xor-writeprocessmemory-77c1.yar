rule TTP_XOR_WriteProcessMemory_77c1 {
  strings:
    $key_77c1 = { 20 b3 [2] 12 91 [2] 14 a4 [2] 3a a4 [2] 05 b8 }

  condition:
    any of them
}