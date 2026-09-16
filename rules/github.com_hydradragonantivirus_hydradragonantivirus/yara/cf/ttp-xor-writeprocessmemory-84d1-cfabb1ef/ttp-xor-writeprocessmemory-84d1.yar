rule TTP_XOR_WriteProcessMemory_84d1 {
  strings:
    $key_84d1 = { d3 a3 [2] e1 81 [2] e7 b4 [2] c9 b4 [2] f6 a8 }

  condition:
    any of them
}