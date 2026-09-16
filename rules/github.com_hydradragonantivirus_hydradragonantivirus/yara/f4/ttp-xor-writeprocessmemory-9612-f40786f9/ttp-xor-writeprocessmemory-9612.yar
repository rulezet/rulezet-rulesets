rule TTP_XOR_WriteProcessMemory_9612 {
  strings:
    $key_9612 = { c1 60 [2] f3 42 [2] f5 77 [2] db 77 [2] e4 6b }

  condition:
    any of them
}