rule TTP_XOR_WriteProcessMemory_d5d4 {
  strings:
    $key_d5d4 = { 82 a6 [2] b0 84 [2] b6 b1 [2] 98 b1 [2] a7 ad }

  condition:
    any of them
}