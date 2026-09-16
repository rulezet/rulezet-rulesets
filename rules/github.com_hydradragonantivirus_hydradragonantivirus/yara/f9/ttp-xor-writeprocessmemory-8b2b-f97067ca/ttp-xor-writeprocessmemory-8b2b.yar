rule TTP_XOR_WriteProcessMemory_8b2b {
  strings:
    $key_8b2b = { dc 59 [2] ee 7b [2] e8 4e [2] c6 4e [2] f9 52 }

  condition:
    any of them
}