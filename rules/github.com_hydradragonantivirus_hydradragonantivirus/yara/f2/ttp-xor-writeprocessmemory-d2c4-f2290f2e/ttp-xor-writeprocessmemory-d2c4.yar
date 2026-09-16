rule TTP_XOR_WriteProcessMemory_d2c4 {
  strings:
    $key_d2c4 = { 85 b6 [2] b7 94 [2] b1 a1 [2] 9f a1 [2] a0 bd }

  condition:
    any of them
}