rule TTP_XOR_WriteProcessMemory_8b42 {
  strings:
    $key_8b42 = { dc 30 [2] ee 12 [2] e8 27 [2] c6 27 [2] f9 3b }

  condition:
    any of them
}