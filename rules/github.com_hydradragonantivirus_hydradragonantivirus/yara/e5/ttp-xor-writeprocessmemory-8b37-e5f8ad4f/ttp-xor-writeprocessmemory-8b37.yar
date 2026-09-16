rule TTP_XOR_WriteProcessMemory_8b37 {
  strings:
    $key_8b37 = { dc 45 [2] ee 67 [2] e8 52 [2] c6 52 [2] f9 4e }

  condition:
    any of them
}