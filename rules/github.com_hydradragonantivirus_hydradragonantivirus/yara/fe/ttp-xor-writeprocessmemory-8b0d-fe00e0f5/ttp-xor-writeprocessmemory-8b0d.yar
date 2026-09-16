rule TTP_XOR_WriteProcessMemory_8b0d {
  strings:
    $key_8b0d = { dc 7f [2] ee 5d [2] e8 68 [2] c6 68 [2] f9 74 }

  condition:
    any of them
}