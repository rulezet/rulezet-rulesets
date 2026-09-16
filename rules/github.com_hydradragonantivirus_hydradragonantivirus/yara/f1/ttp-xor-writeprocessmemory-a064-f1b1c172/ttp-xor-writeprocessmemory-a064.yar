rule TTP_XOR_WriteProcessMemory_a064 {
  strings:
    $key_a064 = { f7 16 [2] c5 34 [2] c3 01 [2] ed 01 [2] d2 1d }

  condition:
    any of them
}