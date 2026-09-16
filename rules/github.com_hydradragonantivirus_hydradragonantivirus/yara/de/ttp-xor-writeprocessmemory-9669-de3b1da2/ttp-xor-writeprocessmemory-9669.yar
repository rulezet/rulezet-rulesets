rule TTP_XOR_WriteProcessMemory_9669 {
  strings:
    $key_9669 = { c1 1b [2] f3 39 [2] f5 0c [2] db 0c [2] e4 10 }

  condition:
    any of them
}