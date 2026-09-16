rule TTP_XOR_WriteProcessMemory_8b62 {
  strings:
    $key_8b62 = { dc 10 [2] ee 32 [2] e8 07 [2] c6 07 [2] f9 1b }

  condition:
    any of them
}