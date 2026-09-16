rule TTP_XOR_WriteProcessMemory_a0f5 {
  strings:
    $key_a0f5 = { f7 87 [2] c5 a5 [2] c3 90 [2] ed 90 [2] d2 8c }

  condition:
    any of them
}