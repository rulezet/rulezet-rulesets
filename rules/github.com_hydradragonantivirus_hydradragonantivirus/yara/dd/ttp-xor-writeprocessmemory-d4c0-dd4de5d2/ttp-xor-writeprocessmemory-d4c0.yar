rule TTP_XOR_WriteProcessMemory_d4c0 {
  strings:
    $key_d4c0 = { 83 b2 [2] b1 90 [2] b7 a5 [2] 99 a5 [2] a6 b9 }

  condition:
    any of them
}