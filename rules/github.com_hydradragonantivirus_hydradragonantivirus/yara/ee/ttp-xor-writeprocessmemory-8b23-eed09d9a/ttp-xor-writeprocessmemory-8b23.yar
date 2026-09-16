rule TTP_XOR_WriteProcessMemory_8b23 {
  strings:
    $key_8b23 = { dc 51 [2] ee 73 [2] e8 46 [2] c6 46 [2] f9 5a }

  condition:
    any of them
}