rule TTP_XOR_WriteProcessMemory_84b4 {
  strings:
    $key_84b4 = { d3 c6 [2] e1 e4 [2] e7 d1 [2] c9 d1 [2] f6 cd }

  condition:
    any of them
}