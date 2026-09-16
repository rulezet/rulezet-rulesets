rule TTP_XOR_WriteProcessMemory_d2c5 {
  strings:
    $key_d2c5 = { 85 b7 [2] b7 95 [2] b1 a0 [2] 9f a0 [2] a0 bc }

  condition:
    any of them
}