rule TTP_XOR_WriteProcessMemory_8b85 {
  strings:
    $key_8b85 = { dc f7 [2] ee d5 [2] e8 e0 [2] c6 e0 [2] f9 fc }

  condition:
    any of them
}