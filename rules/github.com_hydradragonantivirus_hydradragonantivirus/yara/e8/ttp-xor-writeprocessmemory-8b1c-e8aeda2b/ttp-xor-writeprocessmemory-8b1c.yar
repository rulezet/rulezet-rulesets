rule TTP_XOR_WriteProcessMemory_8b1c {
  strings:
    $key_8b1c = { dc 6e [2] ee 4c [2] e8 79 [2] c6 79 [2] f9 65 }

  condition:
    any of them
}