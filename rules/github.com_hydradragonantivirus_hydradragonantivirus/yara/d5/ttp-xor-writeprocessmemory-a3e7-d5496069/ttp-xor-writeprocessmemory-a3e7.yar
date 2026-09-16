rule TTP_XOR_WriteProcessMemory_a3e7 {
  strings:
    $key_a3e7 = { f4 95 [2] c6 b7 [2] c0 82 [2] ee 82 [2] d1 9e }

  condition:
    any of them
}