rule TTP_XOR_WriteProcessMemory_9266 {
  strings:
    $key_9266 = { c5 14 [2] f7 36 [2] f1 03 [2] df 03 [2] e0 1f }

  condition:
    any of them
}