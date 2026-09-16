rule TTP_XOR_WriteProcessMemory_9526 {
  strings:
    $key_9526 = { c2 54 [2] f0 76 [2] f6 43 [2] d8 43 [2] e7 5f }

  condition:
    any of them
}