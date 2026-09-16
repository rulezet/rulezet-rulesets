rule TTP_XOR_WriteProcessMemory_8b4e {
  strings:
    $key_8b4e = { dc 3c [2] ee 1e [2] e8 2b [2] c6 2b [2] f9 37 }

  condition:
    any of them
}