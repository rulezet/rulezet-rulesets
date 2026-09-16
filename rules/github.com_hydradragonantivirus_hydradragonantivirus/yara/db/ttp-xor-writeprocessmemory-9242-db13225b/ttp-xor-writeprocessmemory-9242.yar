rule TTP_XOR_WriteProcessMemory_9242 {
  strings:
    $key_9242 = { c5 30 [2] f7 12 [2] f1 27 [2] df 27 [2] e0 3b }

  condition:
    any of them
}