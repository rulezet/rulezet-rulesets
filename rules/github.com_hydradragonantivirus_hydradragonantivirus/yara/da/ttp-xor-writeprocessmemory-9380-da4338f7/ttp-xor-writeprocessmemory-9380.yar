rule TTP_XOR_WriteProcessMemory_9380 {
  strings:
    $key_9380 = { c4 f2 [2] f6 d0 [2] f0 e5 [2] de e5 [2] e1 f9 }

  condition:
    any of them
}