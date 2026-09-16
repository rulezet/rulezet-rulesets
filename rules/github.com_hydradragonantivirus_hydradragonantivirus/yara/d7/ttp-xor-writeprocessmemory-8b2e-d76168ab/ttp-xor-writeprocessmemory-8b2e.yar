rule TTP_XOR_WriteProcessMemory_8b2e {
  strings:
    $key_8b2e = { dc 5c [2] ee 7e [2] e8 4b [2] c6 4b [2] f9 57 }

  condition:
    any of them
}