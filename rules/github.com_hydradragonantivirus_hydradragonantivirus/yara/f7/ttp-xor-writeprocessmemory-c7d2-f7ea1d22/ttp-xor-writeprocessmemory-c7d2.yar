rule TTP_XOR_WriteProcessMemory_c7d2 {
  strings:
    $key_c7d2 = { 90 a0 [2] a2 82 [2] a4 b7 [2] 8a b7 [2] b5 ab }

  condition:
    any of them
}