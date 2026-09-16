rule TTP_XOR_WriteProcessMemory_a3f7 {
  strings:
    $key_a3f7 = { f4 85 [2] c6 a7 [2] c0 92 [2] ee 92 [2] d1 8e }

  condition:
    any of them
}