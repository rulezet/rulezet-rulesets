rule TTP_XOR_WriteProcessMemory_84a1 {
  strings:
    $key_84a1 = { d3 d3 [2] e1 f1 [2] e7 c4 [2] c9 c4 [2] f6 d8 }

  condition:
    any of them
}