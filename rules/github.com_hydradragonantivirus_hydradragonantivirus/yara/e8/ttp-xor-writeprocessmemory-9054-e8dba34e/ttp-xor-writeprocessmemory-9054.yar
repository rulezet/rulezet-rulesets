rule TTP_XOR_WriteProcessMemory_9054 {
  strings:
    $key_9054 = { c7 26 [2] f5 04 [2] f3 31 [2] dd 31 [2] e2 2d }

  condition:
    any of them
}