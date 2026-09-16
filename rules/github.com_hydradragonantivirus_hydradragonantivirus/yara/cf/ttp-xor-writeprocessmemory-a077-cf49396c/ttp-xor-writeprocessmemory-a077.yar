rule TTP_XOR_WriteProcessMemory_a077 {
  strings:
    $key_a077 = { f7 05 [2] c5 27 [2] c3 12 [2] ed 12 [2] d2 0e }

  condition:
    any of them
}