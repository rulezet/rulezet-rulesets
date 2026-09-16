rule TTP_XOR_WriteProcessMemory_a374 {
  strings:
    $key_a374 = { f4 06 [2] c6 24 [2] c0 11 [2] ee 11 [2] d1 0d }

  condition:
    any of them
}