rule TTP_XOR_WriteProcessMemory_a65b {
  strings:
    $key_a65b = { f1 29 [2] c3 0b [2] c5 3e [2] eb 3e [2] d4 22 }

  condition:
    any of them
}