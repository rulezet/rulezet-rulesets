rule TTP_XOR_WriteProcessMemory_9605 {
  strings:
    $key_9605 = { c1 77 [2] f3 55 [2] f5 60 [2] db 60 [2] e4 7c }

  condition:
    any of them
}