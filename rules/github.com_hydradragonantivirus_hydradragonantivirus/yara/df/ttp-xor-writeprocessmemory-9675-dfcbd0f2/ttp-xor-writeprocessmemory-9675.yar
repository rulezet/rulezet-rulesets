rule TTP_XOR_WriteProcessMemory_9675 {
  strings:
    $key_9675 = { c1 07 [2] f3 25 [2] f5 10 [2] db 10 [2] e4 0c }

  condition:
    any of them
}