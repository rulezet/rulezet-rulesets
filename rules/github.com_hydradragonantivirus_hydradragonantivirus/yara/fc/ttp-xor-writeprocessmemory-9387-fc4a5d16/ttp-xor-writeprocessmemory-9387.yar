rule TTP_XOR_WriteProcessMemory_9387 {
  strings:
    $key_9387 = { c4 f5 [2] f6 d7 [2] f0 e2 [2] de e2 [2] e1 fe }

  condition:
    any of them
}