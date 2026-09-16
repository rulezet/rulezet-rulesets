rule TTP_XOR_WriteProcessMemory_9381 {
  strings:
    $key_9381 = { c4 f3 [2] f6 d1 [2] f0 e4 [2] de e4 [2] e1 f8 }

  condition:
    any of them
}