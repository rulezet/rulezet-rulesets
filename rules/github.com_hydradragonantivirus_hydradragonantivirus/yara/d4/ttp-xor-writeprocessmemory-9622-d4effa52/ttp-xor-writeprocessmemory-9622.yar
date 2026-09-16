rule TTP_XOR_WriteProcessMemory_9622 {
  strings:
    $key_9622 = { c1 50 [2] f3 72 [2] f5 47 [2] db 47 [2] e4 5b }

  condition:
    any of them
}