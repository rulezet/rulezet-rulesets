rule TTP_XOR_WriteProcessMemory_a0f0 {
  strings:
    $key_a0f0 = { f7 82 [2] c5 a0 [2] c3 95 [2] ed 95 [2] d2 89 }

  condition:
    any of them
}