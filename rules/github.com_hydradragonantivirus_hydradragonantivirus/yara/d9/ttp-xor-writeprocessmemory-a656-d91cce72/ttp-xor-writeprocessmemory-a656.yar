rule TTP_XOR_WriteProcessMemory_a656 {
  strings:
    $key_a656 = { f1 24 [2] c3 06 [2] c5 33 [2] eb 33 [2] d4 2f }

  condition:
    any of them
}