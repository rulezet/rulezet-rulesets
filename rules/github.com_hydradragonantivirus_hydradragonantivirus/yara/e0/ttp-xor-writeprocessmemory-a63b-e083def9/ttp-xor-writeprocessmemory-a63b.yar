rule TTP_XOR_WriteProcessMemory_a63b {
  strings:
    $key_a63b = { f1 49 [2] c3 6b [2] c5 5e [2] eb 5e [2] d4 42 }

  condition:
    any of them
}