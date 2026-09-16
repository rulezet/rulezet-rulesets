rule TTP_XOR_WriteProcessMemory_87a4 {
  strings:
    $key_87a4 = { d0 d6 [2] e2 f4 [2] e4 c1 [2] ca c1 [2] f5 dd }

  condition:
    any of them
}