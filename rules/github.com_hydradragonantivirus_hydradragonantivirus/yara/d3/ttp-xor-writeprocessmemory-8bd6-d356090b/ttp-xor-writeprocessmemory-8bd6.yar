rule TTP_XOR_WriteProcessMemory_8bd6 {
  strings:
    $key_8bd6 = { dc a4 [2] ee 86 [2] e8 b3 [2] c6 b3 [2] f9 af }

  condition:
    any of them
}