rule TTP_XOR_WriteProcessMemory_a340 {
  strings:
    $key_a340 = { f4 32 [2] c6 10 [2] c0 25 [2] ee 25 [2] d1 39 }

  condition:
    any of them
}