rule TTP_XOR_WriteProcessMemory_8b3d {
  strings:
    $key_8b3d = { dc 4f [2] ee 6d [2] e8 58 [2] c6 58 [2] f9 44 }

  condition:
    any of them
}