rule TTP_XOR_WriteProcessMemory_9030 {
  strings:
    $key_9030 = { c7 42 [2] f5 60 [2] f3 55 [2] dd 55 [2] e2 49 }

  condition:
    any of them
}