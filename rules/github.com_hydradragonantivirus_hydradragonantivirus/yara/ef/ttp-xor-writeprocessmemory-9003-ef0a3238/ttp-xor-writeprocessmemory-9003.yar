rule TTP_XOR_WriteProcessMemory_9003 {
  strings:
    $key_9003 = { c7 71 [2] f5 53 [2] f3 66 [2] dd 66 [2] e2 7a }

  condition:
    any of them
}