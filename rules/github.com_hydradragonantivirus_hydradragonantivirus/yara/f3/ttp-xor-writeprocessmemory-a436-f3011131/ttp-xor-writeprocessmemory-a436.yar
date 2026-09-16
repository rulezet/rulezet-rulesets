rule TTP_XOR_WriteProcessMemory_a436 {
  strings:
    $key_a436 = { f3 44 [2] c1 66 [2] c7 53 [2] e9 53 [2] d6 4f }

  condition:
    any of them
}