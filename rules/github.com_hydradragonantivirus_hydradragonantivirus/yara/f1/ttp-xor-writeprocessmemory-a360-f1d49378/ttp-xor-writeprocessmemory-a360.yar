rule TTP_XOR_WriteProcessMemory_a360 {
  strings:
    $key_a360 = { f4 12 [2] c6 30 [2] c0 05 [2] ee 05 [2] d1 19 }

  condition:
    any of them
}