rule TTP_XOR_WriteProcessMemory_9441 {
  strings:
    $key_9441 = { c3 33 [2] f1 11 [2] f7 24 [2] d9 24 [2] e6 38 }

  condition:
    any of them
}