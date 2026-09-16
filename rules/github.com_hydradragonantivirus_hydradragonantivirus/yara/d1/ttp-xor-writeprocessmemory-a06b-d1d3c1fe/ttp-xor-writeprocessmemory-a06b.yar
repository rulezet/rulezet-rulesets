rule TTP_XOR_WriteProcessMemory_a06b {
  strings:
    $key_a06b = { f7 19 [2] c5 3b [2] c3 0e [2] ed 0e [2] d2 12 }

  condition:
    any of them
}