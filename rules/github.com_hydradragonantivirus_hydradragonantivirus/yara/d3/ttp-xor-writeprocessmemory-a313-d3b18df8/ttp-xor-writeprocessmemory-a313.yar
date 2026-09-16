rule TTP_XOR_WriteProcessMemory_a313 {
  strings:
    $key_a313 = { f4 61 [2] c6 43 [2] c0 76 [2] ee 76 [2] d1 6a }

  condition:
    any of them
}