rule TTP_XOR_WriteProcessMemory_72d4 {
  strings:
    $key_72d4 = { 25 a6 [2] 17 84 [2] 11 b1 [2] 3f b1 [2] 00 ad }

  condition:
    any of them
}