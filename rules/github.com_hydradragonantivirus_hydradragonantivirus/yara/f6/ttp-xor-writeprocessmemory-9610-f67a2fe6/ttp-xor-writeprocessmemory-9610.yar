rule TTP_XOR_WriteProcessMemory_9610 {
  strings:
    $key_9610 = { c1 62 [2] f3 40 [2] f5 75 [2] db 75 [2] e4 69 }

  condition:
    any of them
}