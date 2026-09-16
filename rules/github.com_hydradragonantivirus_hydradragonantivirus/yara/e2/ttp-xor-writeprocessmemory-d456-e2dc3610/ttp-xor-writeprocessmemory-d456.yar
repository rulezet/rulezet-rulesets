rule TTP_XOR_WriteProcessMemory_d456 {
  strings:
    $key_d456 = { 83 24 [2] b1 06 [2] b7 33 [2] 99 33 [2] a6 2f }

  condition:
    any of them
}