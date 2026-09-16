rule TTP_XOR_WriteProcessMemory_84a4 {
  strings:
    $key_84a4 = { d3 d6 [2] e1 f4 [2] e7 c1 [2] c9 c1 [2] f6 dd }

  condition:
    any of them
}