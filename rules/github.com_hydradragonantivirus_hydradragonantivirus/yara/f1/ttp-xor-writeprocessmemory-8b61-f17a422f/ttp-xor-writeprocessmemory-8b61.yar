rule TTP_XOR_WriteProcessMemory_8b61 {
  strings:
    $key_8b61 = { dc 13 [2] ee 31 [2] e8 04 [2] c6 04 [2] f9 18 }

  condition:
    any of them
}