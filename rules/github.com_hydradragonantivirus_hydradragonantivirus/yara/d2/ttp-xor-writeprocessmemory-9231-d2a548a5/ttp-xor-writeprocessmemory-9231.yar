rule TTP_XOR_WriteProcessMemory_9231 {
  strings:
    $key_9231 = { c5 43 [2] f7 61 [2] f1 54 [2] df 54 [2] e0 48 }

  condition:
    any of them
}