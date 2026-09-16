rule TTP_XOR_WriteProcessMemory_d5c0 {
  strings:
    $key_d5c0 = { 82 b2 [2] b0 90 [2] b6 a5 [2] 98 a5 [2] a7 b9 }

  condition:
    any of them
}