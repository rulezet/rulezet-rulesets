rule TTP_XOR_WriteProcessMemory_8461 {
  strings:
    $key_8461 = { d3 13 [2] e1 31 [2] e7 04 [2] c9 04 [2] f6 18 }

  condition:
    any of them
}