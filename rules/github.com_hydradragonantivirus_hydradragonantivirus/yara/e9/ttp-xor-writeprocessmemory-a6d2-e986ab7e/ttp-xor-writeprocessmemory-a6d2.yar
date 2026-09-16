rule TTP_XOR_WriteProcessMemory_a6d2 {
  strings:
    $key_a6d2 = { f1 a0 [2] c3 82 [2] c5 b7 [2] eb b7 [2] d4 ab }

  condition:
    any of them
}