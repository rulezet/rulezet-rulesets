rule TTP_XOR_WriteProcessMemory_9651 {
  strings:
    $key_9651 = { c1 23 [2] f3 01 [2] f5 34 [2] db 34 [2] e4 28 }

  condition:
    any of them
}