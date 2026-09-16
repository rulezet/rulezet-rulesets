rule TTP_XOR_WriteProcessMemory_8442 {
  strings:
    $key_8442 = { d3 30 [2] e1 12 [2] e7 27 [2] c9 27 [2] f6 3b }

  condition:
    any of them
}