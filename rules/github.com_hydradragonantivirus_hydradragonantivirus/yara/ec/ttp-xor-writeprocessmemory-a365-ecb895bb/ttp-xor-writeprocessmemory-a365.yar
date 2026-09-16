rule TTP_XOR_WriteProcessMemory_a365 {
  strings:
    $key_a365 = { f4 17 [2] c6 35 [2] c0 00 [2] ee 00 [2] d1 1c }

  condition:
    any of them
}