rule TTP_XOR_WriteProcessMemory_84e4 {
  strings:
    $key_84e4 = { d3 96 [2] e1 b4 [2] e7 81 [2] c9 81 [2] f6 9d }

  condition:
    any of them
}