rule TTP_XOR_WriteProcessMemory_84d6 {
  strings:
    $key_84d6 = { d3 a4 [2] e1 86 [2] e7 b3 [2] c9 b3 [2] f6 af }

  condition:
    any of them
}