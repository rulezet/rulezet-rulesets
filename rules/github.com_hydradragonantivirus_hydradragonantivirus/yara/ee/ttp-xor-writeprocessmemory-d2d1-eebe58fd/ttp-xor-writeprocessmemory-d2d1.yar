rule TTP_XOR_WriteProcessMemory_d2d1 {
  strings:
    $key_d2d1 = { 85 a3 [2] b7 81 [2] b1 b4 [2] 9f b4 [2] a0 a8 }

  condition:
    any of them
}