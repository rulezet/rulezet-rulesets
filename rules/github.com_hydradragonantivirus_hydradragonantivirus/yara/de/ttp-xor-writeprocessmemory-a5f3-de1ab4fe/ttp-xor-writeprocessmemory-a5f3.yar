rule TTP_XOR_WriteProcessMemory_a5f3 {
  strings:
    $key_a5f3 = { f2 81 [2] c0 a3 [2] c6 96 [2] e8 96 [2] d7 8a }

  condition:
    any of them
}