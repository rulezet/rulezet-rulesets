rule TTP_XOR_WriteProcessMemory_8b45 {
  strings:
    $key_8b45 = { dc 37 [2] ee 15 [2] e8 20 [2] c6 20 [2] f9 3c }

  condition:
    any of them
}