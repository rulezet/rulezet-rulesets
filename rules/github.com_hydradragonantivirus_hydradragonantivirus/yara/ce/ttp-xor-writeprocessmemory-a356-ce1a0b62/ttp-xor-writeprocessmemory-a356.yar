rule TTP_XOR_WriteProcessMemory_a356 {
  strings:
    $key_a356 = { f4 24 [2] c6 06 [2] c0 33 [2] ee 33 [2] d1 2f }

  condition:
    any of them
}