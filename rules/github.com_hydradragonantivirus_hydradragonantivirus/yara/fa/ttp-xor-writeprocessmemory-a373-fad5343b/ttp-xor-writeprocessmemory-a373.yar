rule TTP_XOR_WriteProcessMemory_a373 {
  strings:
    $key_a373 = { f4 01 [2] c6 23 [2] c0 16 [2] ee 16 [2] d1 0a }

  condition:
    any of them
}