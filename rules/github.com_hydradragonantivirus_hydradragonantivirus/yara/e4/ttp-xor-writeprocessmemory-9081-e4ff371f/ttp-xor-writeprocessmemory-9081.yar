rule TTP_XOR_WriteProcessMemory_9081 {
  strings:
    $key_9081 = { c7 f3 [2] f5 d1 [2] f3 e4 [2] dd e4 [2] e2 f8 }

  condition:
    any of them
}