rule TTP_XOR_WriteProcessMemory_9269 {
  strings:
    $key_9269 = { c5 1b [2] f7 39 [2] f1 0c [2] df 0c [2] e0 10 }

  condition:
    any of them
}