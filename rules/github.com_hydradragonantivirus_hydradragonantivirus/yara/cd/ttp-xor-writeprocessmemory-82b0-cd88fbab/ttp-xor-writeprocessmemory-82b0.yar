rule TTP_XOR_WriteProcessMemory_82b0 {
  strings:
    $key_82b0 = { d5 c2 [2] e7 e0 [2] e1 d5 [2] cf d5 [2] f0 c9 }

  condition:
    any of them
}