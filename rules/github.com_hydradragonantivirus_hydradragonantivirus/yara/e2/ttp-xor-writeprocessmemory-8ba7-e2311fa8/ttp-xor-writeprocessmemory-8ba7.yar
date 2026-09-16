rule TTP_XOR_WriteProcessMemory_8ba7 {
  strings:
    $key_8ba7 = { dc d5 [2] ee f7 [2] e8 c2 [2] c6 c2 [2] f9 de }

  condition:
    any of them
}