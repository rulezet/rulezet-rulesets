rule TTP_XOR_WriteProcessMemory_8b66 {
  strings:
    $key_8b66 = { dc 14 [2] ee 36 [2] e8 03 [2] c6 03 [2] f9 1f }

  condition:
    any of them
}