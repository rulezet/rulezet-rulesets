rule TTP_XOR_WriteProcessMemory_76d4 {
  strings:
    $key_76d4 = { 21 a6 [2] 13 84 [2] 15 b1 [2] 3b b1 [2] 04 ad }

  condition:
    any of them
}