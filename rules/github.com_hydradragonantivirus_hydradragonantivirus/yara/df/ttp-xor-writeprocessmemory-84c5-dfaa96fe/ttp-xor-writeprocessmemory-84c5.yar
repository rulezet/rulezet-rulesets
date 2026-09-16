rule TTP_XOR_WriteProcessMemory_84c5 {
  strings:
    $key_84c5 = { d3 b7 [2] e1 95 [2] e7 a0 [2] c9 a0 [2] f6 bc }

  condition:
    any of them
}