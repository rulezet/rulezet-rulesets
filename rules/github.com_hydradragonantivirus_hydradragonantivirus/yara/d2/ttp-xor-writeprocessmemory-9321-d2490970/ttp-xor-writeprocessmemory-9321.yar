rule TTP_XOR_WriteProcessMemory_9321 {
  strings:
    $key_9321 = { c4 53 [2] f6 71 [2] f0 44 [2] de 44 [2] e1 58 }

  condition:
    any of them
}