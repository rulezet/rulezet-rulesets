rule TTP_XOR_WriteProcessMemory_8bcb {
  strings:
    $key_8bcb = { dc b9 [2] ee 9b [2] e8 ae [2] c6 ae [2] f9 b2 }

  condition:
    any of them
}