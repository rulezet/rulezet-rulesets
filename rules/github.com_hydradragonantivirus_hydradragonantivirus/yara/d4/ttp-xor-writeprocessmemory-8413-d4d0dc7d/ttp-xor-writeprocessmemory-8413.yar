rule TTP_XOR_WriteProcessMemory_8413 {
  strings:
    $key_8413 = { d3 61 [2] e1 43 [2] e7 76 [2] c9 76 [2] f6 6a }

  condition:
    any of them
}