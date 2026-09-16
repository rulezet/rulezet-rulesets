rule TTP_XOR_WriteProcessMemory_9635 {
  strings:
    $key_9635 = { c1 47 [2] f3 65 [2] f5 50 [2] db 50 [2] e4 4c }

  condition:
    any of them
}