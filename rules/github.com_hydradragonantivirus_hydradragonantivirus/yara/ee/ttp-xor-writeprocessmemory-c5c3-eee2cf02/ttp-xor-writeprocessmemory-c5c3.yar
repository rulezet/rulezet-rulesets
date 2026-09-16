rule TTP_XOR_WriteProcessMemory_c5c3 {
  strings:
    $key_c5c3 = { 92 b1 [2] a0 93 [2] a6 a6 [2] 88 a6 [2] b7 ba }

  condition:
    any of them
}