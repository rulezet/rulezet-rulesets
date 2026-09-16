rule TTP_XOR_WriteProcessMemory_9632 {
  strings:
    $key_9632 = { c1 40 [2] f3 62 [2] f5 57 [2] db 57 [2] e4 4b }

  condition:
    any of them
}