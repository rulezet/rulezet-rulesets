rule TTP_XOR_WriteProcessMemory_a0d2 {
  strings:
    $key_a0d2 = { f7 a0 [2] c5 82 [2] c3 b7 [2] ed b7 [2] d2 ab }

  condition:
    any of them
}