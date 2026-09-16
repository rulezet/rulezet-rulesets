rule TTP_XOR_WriteProcessMemory_9207 {
  strings:
    $key_9207 = { c5 75 [2] f7 57 [2] f1 62 [2] df 62 [2] e0 7e }

  condition:
    any of them
}