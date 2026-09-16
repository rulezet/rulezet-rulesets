rule TTP_XOR_WriteProcessMemory_9729 {
  strings:
    $key_9729 = { c0 5b [2] f2 79 [2] f4 4c [2] da 4c [2] e5 50 }

  condition:
    any of them
}