rule TTP_XOR_WriteProcessMemory_9452 {
  strings:
    $key_9452 = { c3 20 [2] f1 02 [2] f7 37 [2] d9 37 [2] e6 2b }

  condition:
    any of them
}