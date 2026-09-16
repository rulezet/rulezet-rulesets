rule TTP_XOR_WriteProcessMemory_8ba0 {
  strings:
    $key_8ba0 = { dc d2 [2] ee f0 [2] e8 c5 [2] c6 c5 [2] f9 d9 }

  condition:
    any of them
}