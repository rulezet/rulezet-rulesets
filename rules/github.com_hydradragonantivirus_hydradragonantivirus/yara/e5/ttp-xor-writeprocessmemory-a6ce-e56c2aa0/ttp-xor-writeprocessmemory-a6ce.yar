rule TTP_XOR_WriteProcessMemory_a6ce {
  strings:
    $key_a6ce = { f1 bc [2] c3 9e [2] c5 ab [2] eb ab [2] d4 b7 }

  condition:
    any of them
}