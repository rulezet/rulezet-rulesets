rule TTP_XOR_WriteProcessMemory_a301 {
  strings:
    $key_a301 = { f4 73 [2] c6 51 [2] c0 64 [2] ee 64 [2] d1 78 }

  condition:
    any of them
}