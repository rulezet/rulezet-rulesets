rule TTP_XOR_WriteProcessMemory_87b0 {
  strings:
    $key_87b0 = { d0 c2 [2] e2 e0 [2] e4 d5 [2] ca d5 [2] f5 c9 }

  condition:
    any of them
}