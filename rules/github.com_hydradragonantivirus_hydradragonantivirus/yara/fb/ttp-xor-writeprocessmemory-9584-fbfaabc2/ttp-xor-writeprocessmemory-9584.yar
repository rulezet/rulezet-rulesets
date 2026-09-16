rule TTP_XOR_WriteProcessMemory_9584 {
  strings:
    $key_9584 = { c2 f6 [2] f0 d4 [2] f6 e1 [2] d8 e1 [2] e7 fd }

  condition:
    any of them
}