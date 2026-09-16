rule TTP_XOR_WriteProcessMemory_82a4 {
  strings:
    $key_82a4 = { d5 d6 [2] e7 f4 [2] e1 c1 [2] cf c1 [2] f0 dd }

  condition:
    any of them
}