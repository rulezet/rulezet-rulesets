rule TTP_XOR_WriteProcessMemory_9051 {
  strings:
    $key_9051 = { c7 23 [2] f5 01 [2] f3 34 [2] dd 34 [2] e2 28 }

  condition:
    any of them
}