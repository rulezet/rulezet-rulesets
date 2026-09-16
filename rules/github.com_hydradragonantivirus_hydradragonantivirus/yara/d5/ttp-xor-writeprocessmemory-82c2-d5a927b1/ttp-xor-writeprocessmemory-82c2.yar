rule TTP_XOR_WriteProcessMemory_82c2 {
  strings:
    $key_82c2 = { d5 b0 [2] e7 92 [2] e1 a7 [2] cf a7 [2] f0 bb }

  condition:
    any of them
}