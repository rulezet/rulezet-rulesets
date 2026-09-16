rule TTP_XOR_WriteProcessMemory_8bce {
  strings:
    $key_8bce = { dc bc [2] ee 9e [2] e8 ab [2] c6 ab [2] f9 b7 }

  condition:
    any of them
}