rule TTP_XOR_WriteProcessMemory_a3f2 {
  strings:
    $key_a3f2 = { f4 80 [2] c6 a2 [2] c0 97 [2] ee 97 [2] d1 8b }

  condition:
    any of them
}