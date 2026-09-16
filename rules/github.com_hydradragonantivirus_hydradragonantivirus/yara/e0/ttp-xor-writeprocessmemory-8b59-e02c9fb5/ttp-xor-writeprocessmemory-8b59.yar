rule TTP_XOR_WriteProcessMemory_8b59 {
  strings:
    $key_8b59 = { dc 2b [2] ee 09 [2] e8 3c [2] c6 3c [2] f9 20 }

  condition:
    any of them
}