rule TTP_XOR_WriteProcessMemory_9273 {
  strings:
    $key_9273 = { c5 01 [2] f7 23 [2] f1 16 [2] df 16 [2] e0 0a }

  condition:
    any of them
}