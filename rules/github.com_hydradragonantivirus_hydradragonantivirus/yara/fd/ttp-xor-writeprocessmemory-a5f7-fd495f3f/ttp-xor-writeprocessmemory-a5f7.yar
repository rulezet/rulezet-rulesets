rule TTP_XOR_WriteProcessMemory_a5f7 {
  strings:
    $key_a5f7 = { f2 85 [2] c0 a7 [2] c6 92 [2] e8 92 [2] d7 8e }

  condition:
    any of them
}