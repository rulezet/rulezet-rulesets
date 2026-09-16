rule TTP_XOR_WriteProcessMemory_9240 {
  strings:
    $key_9240 = { c5 32 [2] f7 10 [2] f1 25 [2] df 25 [2] e0 39 }

  condition:
    any of them
}