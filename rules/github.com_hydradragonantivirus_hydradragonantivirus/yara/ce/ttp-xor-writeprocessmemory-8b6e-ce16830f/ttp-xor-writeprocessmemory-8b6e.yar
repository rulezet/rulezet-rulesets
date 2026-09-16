rule TTP_XOR_WriteProcessMemory_8b6e {
  strings:
    $key_8b6e = { dc 1c [2] ee 3e [2] e8 0b [2] c6 0b [2] f9 17 }

  condition:
    any of them
}