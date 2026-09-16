rule TTP_XOR_WriteProcessMemory_8bd5 {
  strings:
    $key_8bd5 = { dc a7 [2] ee 85 [2] e8 b0 [2] c6 b0 [2] f9 ac }

  condition:
    any of them
}