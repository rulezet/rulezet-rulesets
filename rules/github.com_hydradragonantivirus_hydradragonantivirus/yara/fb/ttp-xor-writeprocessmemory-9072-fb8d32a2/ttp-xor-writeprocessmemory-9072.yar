rule TTP_XOR_WriteProcessMemory_9072 {
  strings:
    $key_9072 = { c7 00 [2] f5 22 [2] f3 17 [2] dd 17 [2] e2 0b }

  condition:
    any of them
}