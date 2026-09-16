rule TTP_XOR_WriteProcessMemory_84c4 {
  strings:
    $key_84c4 = { d3 b6 [2] e1 94 [2] e7 a1 [2] c9 a1 [2] f6 bd }

  condition:
    any of them
}