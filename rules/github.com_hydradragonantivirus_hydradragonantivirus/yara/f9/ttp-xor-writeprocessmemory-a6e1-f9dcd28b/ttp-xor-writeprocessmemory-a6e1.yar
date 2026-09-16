rule TTP_XOR_WriteProcessMemory_a6e1 {
  strings:
    $key_a6e1 = { f1 93 [2] c3 b1 [2] c5 84 [2] eb 84 [2] d4 98 }

  condition:
    any of them
}