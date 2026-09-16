rule TTP_XOR_WriteProcessMemory_a302 {
  strings:
    $key_a302 = { f4 70 [2] c6 52 [2] c0 67 [2] ee 67 [2] d1 7b }

  condition:
    any of them
}