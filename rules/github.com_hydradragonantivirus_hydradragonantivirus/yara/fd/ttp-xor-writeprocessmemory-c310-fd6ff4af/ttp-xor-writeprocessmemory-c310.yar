rule TTP_XOR_WriteProcessMemory_c310 {
  strings:
    $key_c310 = { 94 62 [2] a6 40 [2] a0 75 [2] 8e 75 [2] b1 69 }

  condition:
    any of them
}