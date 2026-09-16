rule TTP_XOR_WriteProcessMemory_77d0 {
  strings:
    $key_77d0 = { 20 a2 [2] 12 80 [2] 14 b5 [2] 3a b5 [2] 05 a9 }

  condition:
    any of them
}