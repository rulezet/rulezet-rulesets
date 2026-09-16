rule TTP_XOR_WriteProcessMemory_84b2 {
  strings:
    $key_84b2 = { d3 c0 [2] e1 e2 [2] e7 d7 [2] c9 d7 [2] f6 cb }

  condition:
    any of them
}