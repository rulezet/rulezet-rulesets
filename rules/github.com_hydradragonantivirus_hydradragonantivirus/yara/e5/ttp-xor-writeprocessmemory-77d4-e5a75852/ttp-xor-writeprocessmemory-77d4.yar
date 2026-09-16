rule TTP_XOR_WriteProcessMemory_77d4 {
  strings:
    $key_77d4 = { 20 a6 [2] 12 84 [2] 14 b1 [2] 3a b1 [2] 05 ad }

  condition:
    any of them
}