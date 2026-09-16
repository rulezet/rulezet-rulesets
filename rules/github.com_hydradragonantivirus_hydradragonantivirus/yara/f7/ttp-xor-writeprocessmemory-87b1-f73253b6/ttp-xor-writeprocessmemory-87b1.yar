rule TTP_XOR_WriteProcessMemory_87b1 {
  strings:
    $key_87b1 = { d0 c3 [2] e2 e1 [2] e4 d4 [2] ca d4 [2] f5 c8 }

  condition:
    any of them
}