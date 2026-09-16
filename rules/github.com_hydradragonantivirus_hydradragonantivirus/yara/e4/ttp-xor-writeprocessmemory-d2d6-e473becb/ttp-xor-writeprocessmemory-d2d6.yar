rule TTP_XOR_WriteProcessMemory_d2d6 {
  strings:
    $key_d2d6 = { 85 a4 [2] b7 86 [2] b1 b3 [2] 9f b3 [2] a0 af }

  condition:
    any of them
}