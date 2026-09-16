rule TTP_XOR_WriteProcessMemory_9256 {
  strings:
    $key_9256 = { c5 24 [2] f7 06 [2] f1 33 [2] df 33 [2] e0 2f }

  condition:
    any of them
}