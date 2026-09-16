rule TTP_XOR_WriteProcessMemory_9642 {
  strings:
    $key_9642 = { c1 30 [2] f3 12 [2] f5 27 [2] db 27 [2] e4 3b }

  condition:
    any of them
}