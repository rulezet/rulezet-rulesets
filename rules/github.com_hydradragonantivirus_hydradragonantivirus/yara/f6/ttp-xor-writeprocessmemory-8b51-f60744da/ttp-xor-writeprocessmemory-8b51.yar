rule TTP_XOR_WriteProcessMemory_8b51 {
  strings:
    $key_8b51 = { dc 23 [2] ee 01 [2] e8 34 [2] c6 34 [2] f9 28 }

  condition:
    any of them
}