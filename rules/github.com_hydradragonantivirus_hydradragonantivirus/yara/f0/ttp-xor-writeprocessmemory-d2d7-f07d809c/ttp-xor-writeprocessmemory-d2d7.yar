rule TTP_XOR_WriteProcessMemory_d2d7 {
  strings:
    $key_d2d7 = { 85 a5 [2] b7 87 [2] b1 b2 [2] 9f b2 [2] a0 ae }

  condition:
    any of them
}