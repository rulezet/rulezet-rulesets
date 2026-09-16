rule TTP_XOR_WriteProcessMemory_a333 {
  strings:
    $key_a333 = { f4 41 [2] c6 63 [2] c0 56 [2] ee 56 [2] d1 4a }

  condition:
    any of them
}