rule TTP_XOR_WriteProcessMemory_a6e7 {
  strings:
    $key_a6e7 = { f1 95 [2] c3 b7 [2] c5 82 [2] eb 82 [2] d4 9e }

  condition:
    any of them
}