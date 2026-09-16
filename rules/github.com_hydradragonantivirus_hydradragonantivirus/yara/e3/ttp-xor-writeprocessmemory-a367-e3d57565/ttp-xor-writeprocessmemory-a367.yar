rule TTP_XOR_WriteProcessMemory_a367 {
  strings:
    $key_a367 = { f4 15 [2] c6 37 [2] c0 02 [2] ee 02 [2] d1 1e }

  condition:
    any of them
}