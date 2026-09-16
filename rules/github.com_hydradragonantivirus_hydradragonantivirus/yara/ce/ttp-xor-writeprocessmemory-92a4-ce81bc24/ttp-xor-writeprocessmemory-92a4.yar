rule TTP_XOR_WriteProcessMemory_92a4 {
  strings:
    $key_92a4 = { c5 d6 [2] f7 f4 [2] f1 c1 [2] df c1 [2] e0 dd }

  condition:
    any of them
}