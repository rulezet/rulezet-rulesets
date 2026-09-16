rule TTP_XOR_WriteProcessMemory_c5d4 {
  strings:
    $key_c5d4 = { 92 a6 [2] a0 84 [2] a6 b1 [2] 88 b1 [2] b7 ad }

  condition:
    any of them
}