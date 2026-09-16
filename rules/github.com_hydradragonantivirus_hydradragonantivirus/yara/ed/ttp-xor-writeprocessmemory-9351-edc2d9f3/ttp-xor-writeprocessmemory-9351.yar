rule TTP_XOR_WriteProcessMemory_9351 {
  strings:
    $key_9351 = { c4 23 [2] f6 01 [2] f0 34 [2] de 34 [2] e1 28 }

  condition:
    any of them
}