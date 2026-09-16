rule TTP_XOR_WriteProcessMemory_82a7 {
  strings:
    $key_82a7 = { d5 d5 [2] e7 f7 [2] e1 c2 [2] cf c2 [2] f0 de }

  condition:
    any of them
}