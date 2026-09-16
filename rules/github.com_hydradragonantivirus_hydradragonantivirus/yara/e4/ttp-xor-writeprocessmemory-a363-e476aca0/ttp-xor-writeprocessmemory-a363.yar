rule TTP_XOR_WriteProcessMemory_a363 {
  strings:
    $key_a363 = { f4 11 [2] c6 33 [2] c0 06 [2] ee 06 [2] d1 1a }

  condition:
    any of them
}