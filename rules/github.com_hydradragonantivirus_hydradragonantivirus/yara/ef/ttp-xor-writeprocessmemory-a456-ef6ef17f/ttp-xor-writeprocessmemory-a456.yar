rule TTP_XOR_WriteProcessMemory_a456 {
  strings:
    $key_a456 = { f3 24 [2] c1 06 [2] c7 33 [2] e9 33 [2] d6 2f }

  condition:
    any of them
}