rule TTP_XOR_WriteProcessMemory_c3f1 {
  strings:
    $key_c3f1 = { 94 83 [2] a6 a1 [2] a0 94 [2] 8e 94 [2] b1 88 }

  condition:
    any of them
}