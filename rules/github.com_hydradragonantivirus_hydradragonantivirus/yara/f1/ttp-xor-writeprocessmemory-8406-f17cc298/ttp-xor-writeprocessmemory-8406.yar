rule TTP_XOR_WriteProcessMemory_8406 {
  strings:
    $key_8406 = { d3 74 [2] e1 56 [2] e7 63 [2] c9 63 [2] f6 7f }

  condition:
    any of them
}