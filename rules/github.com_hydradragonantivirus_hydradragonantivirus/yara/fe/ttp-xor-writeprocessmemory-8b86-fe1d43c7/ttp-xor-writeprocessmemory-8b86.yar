rule TTP_XOR_WriteProcessMemory_8b86 {
  strings:
    $key_8b86 = { dc f4 [2] ee d6 [2] e8 e3 [2] c6 e3 [2] f9 ff }

  condition:
    any of them
}