rule TTP_XOR_WriteProcessMemory_8b3c {
  strings:
    $key_8b3c = { dc 4e [2] ee 6c [2] e8 59 [2] c6 59 [2] f9 45 }

  condition:
    any of them
}