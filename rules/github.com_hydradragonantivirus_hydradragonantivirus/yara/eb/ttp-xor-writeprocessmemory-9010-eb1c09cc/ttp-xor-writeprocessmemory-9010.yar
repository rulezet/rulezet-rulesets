rule TTP_XOR_WriteProcessMemory_9010 {
  strings:
    $key_9010 = { c7 62 [2] f5 40 [2] f3 75 [2] dd 75 [2] e2 69 }

  condition:
    any of them
}