rule TTP_XOR_WriteProcessMemory_9319 {
  strings:
    $key_9319 = { c4 6b [2] f6 49 [2] f0 7c [2] de 7c [2] e1 60 }

  condition:
    any of them
}