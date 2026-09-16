rule TTP_XOR_WriteProcessMemory_a46b {
  strings:
    $key_a46b = { f3 19 [2] c1 3b [2] c7 0e [2] e9 0e [2] d6 12 }

  condition:
    any of them
}