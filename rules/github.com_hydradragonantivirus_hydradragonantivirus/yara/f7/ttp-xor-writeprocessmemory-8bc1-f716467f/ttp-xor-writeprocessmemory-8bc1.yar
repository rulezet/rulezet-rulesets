rule TTP_XOR_WriteProcessMemory_8bc1 {
  strings:
    $key_8bc1 = { dc b3 [2] ee 91 [2] e8 a4 [2] c6 a4 [2] f9 b8 }

  condition:
    any of them
}