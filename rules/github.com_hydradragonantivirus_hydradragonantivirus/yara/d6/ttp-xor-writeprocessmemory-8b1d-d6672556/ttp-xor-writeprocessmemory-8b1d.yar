rule TTP_XOR_WriteProcessMemory_8b1d {
  strings:
    $key_8b1d = { dc 6f [2] ee 4d [2] e8 78 [2] c6 78 [2] f9 64 }

  condition:
    any of them
}