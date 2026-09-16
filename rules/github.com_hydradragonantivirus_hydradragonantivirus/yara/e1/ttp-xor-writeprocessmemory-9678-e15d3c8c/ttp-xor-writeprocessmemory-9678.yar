rule TTP_XOR_WriteProcessMemory_9678 {
  strings:
    $key_9678 = { c1 0a [2] f3 28 [2] f5 1d [2] db 1d [2] e4 01 }

  condition:
    any of them
}