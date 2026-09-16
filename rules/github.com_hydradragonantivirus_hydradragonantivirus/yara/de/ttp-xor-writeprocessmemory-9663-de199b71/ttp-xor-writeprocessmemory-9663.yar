rule TTP_XOR_WriteProcessMemory_9663 {
  strings:
    $key_9663 = { c1 11 [2] f3 33 [2] f5 06 [2] db 06 [2] e4 1a }

  condition:
    any of them
}