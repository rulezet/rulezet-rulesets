rule TTP_XOR_WriteProcessMemory_8a8f {
  strings:
    $key_8a8f = { dd fd [2] ef df [2] e9 ea [2] c7 ea [2] f8 f6 }

  condition:
    any of them
}