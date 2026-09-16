rule TTP_XOR_WriteProcessMemory_d272 {
  strings:
    $key_d272 = { 85 00 [2] b7 22 [2] b1 17 [2] 9f 17 [2] a0 0b }

  condition:
    any of them
}