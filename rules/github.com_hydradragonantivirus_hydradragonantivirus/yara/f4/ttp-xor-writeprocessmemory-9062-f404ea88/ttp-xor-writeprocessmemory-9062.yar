rule TTP_XOR_WriteProcessMemory_9062 {
  strings:
    $key_9062 = { c7 10 [2] f5 32 [2] f3 07 [2] dd 07 [2] e2 1b }

  condition:
    any of them
}