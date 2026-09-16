rule TTP_XOR_WriteProcessMemory_8b70 {
  strings:
    $key_8b70 = { dc 02 [2] ee 20 [2] e8 15 [2] c6 15 [2] f9 09 }

  condition:
    any of them
}