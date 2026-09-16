rule TTP_XOR_WriteProcessMemory_9203 {
  strings:
    $key_9203 = { c5 71 [2] f7 53 [2] f1 66 [2] df 66 [2] e0 7a }

  condition:
    any of them
}