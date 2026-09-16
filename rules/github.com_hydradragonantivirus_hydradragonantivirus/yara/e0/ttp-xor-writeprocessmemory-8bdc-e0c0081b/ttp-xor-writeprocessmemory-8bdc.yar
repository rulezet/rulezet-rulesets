rule TTP_XOR_WriteProcessMemory_8bdc {
  strings:
    $key_8bdc = { dc ae [2] ee 8c [2] e8 b9 [2] c6 b9 [2] f9 a5 }

  condition:
    any of them
}