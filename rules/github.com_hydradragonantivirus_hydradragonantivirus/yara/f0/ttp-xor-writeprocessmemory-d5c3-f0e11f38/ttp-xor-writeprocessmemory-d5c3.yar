rule TTP_XOR_WriteProcessMemory_d5c3 {
  strings:
    $key_d5c3 = { 82 b1 [2] b0 93 [2] b6 a6 [2] 98 a6 [2] a7 ba }

  condition:
    any of them
}