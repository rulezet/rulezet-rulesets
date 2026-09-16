rule TTP_XOR_WriteProcessMemory_a3f1 {
  strings:
    $key_a3f1 = { f4 83 [2] c6 a1 [2] c0 94 [2] ee 94 [2] d1 88 }

  condition:
    any of them
}