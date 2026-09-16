rule TTP_XOR_WriteProcessMemory_9598 {
  strings:
    $key_9598 = { c2 ea [2] f0 c8 [2] f6 fd [2] d8 fd [2] e7 e1 }

  condition:
    any of them
}