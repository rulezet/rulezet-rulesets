rule TTP_XOR_WriteProcessMemory_84b3 {
  strings:
    $key_84b3 = { d3 c1 [2] e1 e3 [2] e7 d6 [2] c9 d6 [2] f6 ca }

  condition:
    any of them
}