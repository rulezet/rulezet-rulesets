rule TTP_XOR_WriteProcessMemory_9503 {
  strings:
    $key_9503 = { c2 71 [2] f0 53 [2] f6 66 [2] d8 66 [2] e7 7a }

  condition:
    any of them
}