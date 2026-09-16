rule TTP_XOR_WriteProcessMemory_8b92 {
  strings:
    $key_8b92 = { dc e0 [2] ee c2 [2] e8 f7 [2] c6 f7 [2] f9 eb }

  condition:
    any of them
}