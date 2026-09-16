rule TTP_XOR_WriteProcessMemory_a042 {
  strings:
    $key_a042 = { f7 30 [2] c5 12 [2] c3 27 [2] ed 27 [2] d2 3b }

  condition:
    any of them
}