rule TTP_XOR_WriteProcessMemory_c5d2 {
  strings:
    $key_c5d2 = { 92 a0 [2] a0 82 [2] a6 b7 [2] 88 b7 [2] b7 ab }

  condition:
    any of them
}