rule TTP_XOR_WriteProcessMemory_84a0 {
  strings:
    $key_84a0 = { d3 d2 [2] e1 f0 [2] e7 c5 [2] c9 c5 [2] f6 d9 }

  condition:
    any of them
}