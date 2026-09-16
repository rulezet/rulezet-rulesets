rule TTP_XOR_WriteProcessMemory_8aba {
  strings:
    $key_8aba = { dd c8 [2] ef ea [2] e9 df [2] c7 df [2] f8 c3 }

  condition:
    any of them
}