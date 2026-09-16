rule TTP_XOR_WriteProcessMemory_c351 {
  strings:
    $key_c351 = { 94 23 [2] a6 01 [2] a0 34 [2] 8e 34 [2] b1 28 }

  condition:
    any of them
}