rule TTP_XOR_WriteProcessMemory_8b38 {
  strings:
    $key_8b38 = { dc 4a [2] ee 68 [2] e8 5d [2] c6 5d [2] f9 41 }

  condition:
    any of them
}