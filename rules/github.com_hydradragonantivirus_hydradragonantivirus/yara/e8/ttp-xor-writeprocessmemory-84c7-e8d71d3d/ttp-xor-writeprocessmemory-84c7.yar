rule TTP_XOR_WriteProcessMemory_84c7 {
  strings:
    $key_84c7 = { d3 b5 [2] e1 97 [2] e7 a2 [2] c9 a2 [2] f6 be }

  condition:
    any of them
}