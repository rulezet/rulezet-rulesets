rule TTP_XOR_WriteProcessMemory_8b7b {
  strings:
    $key_8b7b = { dc 09 [2] ee 2b [2] e8 1e [2] c6 1e [2] f9 02 }

  condition:
    any of them
}