rule TTP_XOR_WriteProcessMemory_9219 {
  strings:
    $key_9219 = { c5 6b [2] f7 49 [2] f1 7c [2] df 7c [2] e0 60 }

  condition:
    any of them
}