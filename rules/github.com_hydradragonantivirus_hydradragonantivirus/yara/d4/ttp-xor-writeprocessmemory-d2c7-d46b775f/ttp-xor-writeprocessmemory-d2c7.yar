rule TTP_XOR_WriteProcessMemory_d2c7 {
  strings:
    $key_d2c7 = { 85 b5 [2] b7 97 [2] b1 a2 [2] 9f a2 [2] a0 be }

  condition:
    any of them
}