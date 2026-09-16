rule TTP_XOR_WriteProcessMemory_9040 {
  strings:
    $key_9040 = { c7 32 [2] f5 10 [2] f3 25 [2] dd 25 [2] e2 39 }

  condition:
    any of them
}