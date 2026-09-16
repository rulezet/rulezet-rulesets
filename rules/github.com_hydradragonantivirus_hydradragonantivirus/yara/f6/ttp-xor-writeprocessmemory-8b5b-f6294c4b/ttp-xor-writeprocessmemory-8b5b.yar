rule TTP_XOR_WriteProcessMemory_8b5b {
  strings:
    $key_8b5b = { dc 29 [2] ee 0b [2] e8 3e [2] c6 3e [2] f9 22 }

  condition:
    any of them
}