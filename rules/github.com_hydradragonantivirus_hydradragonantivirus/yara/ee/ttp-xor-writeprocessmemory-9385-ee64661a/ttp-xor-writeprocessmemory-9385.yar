rule TTP_XOR_WriteProcessMemory_9385 {
  strings:
    $key_9385 = { c4 f7 [2] f6 d5 [2] f0 e0 [2] de e0 [2] e1 fc }

  condition:
    any of them
}