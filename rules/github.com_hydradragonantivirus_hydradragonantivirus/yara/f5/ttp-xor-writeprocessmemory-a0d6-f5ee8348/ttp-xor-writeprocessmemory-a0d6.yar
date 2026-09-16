rule TTP_XOR_WriteProcessMemory_a0d6 {
  strings:
    $key_a0d6 = { f7 a4 [2] c5 86 [2] c3 b3 [2] ed b3 [2] d2 af }

  condition:
    any of them
}