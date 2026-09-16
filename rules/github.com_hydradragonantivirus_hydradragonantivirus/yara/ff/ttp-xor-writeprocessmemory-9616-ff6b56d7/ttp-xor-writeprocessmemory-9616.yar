rule TTP_XOR_WriteProcessMemory_9616 {
  strings:
    $key_9616 = { c1 64 [2] f3 46 [2] f5 73 [2] db 73 [2] e4 6f }

  condition:
    any of them
}