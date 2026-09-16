rule TTP_XOR_WriteProcessMemory_92a7 {
  strings:
    $key_92a7 = { c5 d5 [2] f7 f7 [2] f1 c2 [2] df c2 [2] e0 de }

  condition:
    any of them
}