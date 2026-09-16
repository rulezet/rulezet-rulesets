rule TTP_XOR_WriteProcessMemory_8b76 {
  strings:
    $key_8b76 = { dc 04 [2] ee 26 [2] e8 13 [2] c6 13 [2] f9 0f }

  condition:
    any of them
}