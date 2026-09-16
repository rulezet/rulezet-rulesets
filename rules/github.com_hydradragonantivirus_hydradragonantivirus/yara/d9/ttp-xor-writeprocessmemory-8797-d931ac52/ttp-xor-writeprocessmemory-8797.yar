rule TTP_XOR_WriteProcessMemory_8797 {
  strings:
    $key_8797 = { d0 e5 [2] e2 c7 [2] e4 f2 [2] ca f2 [2] f5 ee }

  condition:
    any of them
}