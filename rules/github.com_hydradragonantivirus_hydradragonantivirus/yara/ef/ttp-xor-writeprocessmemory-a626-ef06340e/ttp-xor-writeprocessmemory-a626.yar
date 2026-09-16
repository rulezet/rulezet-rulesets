rule TTP_XOR_WriteProcessMemory_a626 {
  strings:
    $key_a626 = { f1 54 [2] c3 76 [2] c5 43 [2] eb 43 [2] d4 5f }

  condition:
    any of them
}