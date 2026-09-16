rule TTP_XOR_WriteProcessMemory_a642 {
  strings:
    $key_a642 = { f1 30 [2] c3 12 [2] c5 27 [2] eb 27 [2] d4 3b }

  condition:
    any of them
}