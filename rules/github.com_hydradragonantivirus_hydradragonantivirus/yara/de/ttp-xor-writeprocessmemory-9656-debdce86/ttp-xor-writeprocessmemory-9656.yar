rule TTP_XOR_WriteProcessMemory_9656 {
  strings:
    $key_9656 = { c1 24 [2] f3 06 [2] f5 33 [2] db 33 [2] e4 2f }

  condition:
    any of them
}