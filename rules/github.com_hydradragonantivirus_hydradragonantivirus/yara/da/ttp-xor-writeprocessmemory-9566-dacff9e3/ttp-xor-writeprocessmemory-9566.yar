rule TTP_XOR_WriteProcessMemory_9566 {
  strings:
    $key_9566 = { c2 14 [2] f0 36 [2] f6 03 [2] d8 03 [2] e7 1f }

  condition:
    any of them
}