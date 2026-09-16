rule TTP_XOR_WriteProcessMemory_9239 {
  strings:
    $key_9239 = { c5 4b [2] f7 69 [2] f1 5c [2] df 5c [2] e0 40 }

  condition:
    any of them
}