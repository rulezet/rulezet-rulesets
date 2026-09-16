rule TTP_XOR_WriteProcessMemory_9024 {
  strings:
    $key_9024 = { c7 56 [2] f5 74 [2] f3 41 [2] dd 41 [2] e2 5d }

  condition:
    any of them
}