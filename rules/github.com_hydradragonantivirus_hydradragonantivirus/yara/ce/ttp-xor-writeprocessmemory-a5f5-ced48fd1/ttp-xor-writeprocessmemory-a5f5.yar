rule TTP_XOR_WriteProcessMemory_a5f5 {
  strings:
    $key_a5f5 = { f2 87 [2] c0 a5 [2] c6 90 [2] e8 90 [2] d7 8c }

  condition:
    any of them
}