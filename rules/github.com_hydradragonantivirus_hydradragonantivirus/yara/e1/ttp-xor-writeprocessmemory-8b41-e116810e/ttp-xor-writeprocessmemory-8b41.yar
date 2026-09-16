rule TTP_XOR_WriteProcessMemory_8b41 {
  strings:
    $key_8b41 = { dc 33 [2] ee 11 [2] e8 24 [2] c6 24 [2] f9 38 }

  condition:
    any of them
}