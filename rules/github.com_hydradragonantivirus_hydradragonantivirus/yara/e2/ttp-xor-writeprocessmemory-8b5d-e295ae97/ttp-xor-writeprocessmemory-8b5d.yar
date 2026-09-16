rule TTP_XOR_WriteProcessMemory_8b5d {
  strings:
    $key_8b5d = { dc 2f [2] ee 0d [2] e8 38 [2] c6 38 [2] f9 24 }

  condition:
    any of them
}