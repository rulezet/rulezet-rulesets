rule TTP_XOR_WriteProcessMemory_84d5 {
  strings:
    $key_84d5 = { d3 a7 [2] e1 85 [2] e7 b0 [2] c9 b0 [2] f6 ac }

  condition:
    any of them
}