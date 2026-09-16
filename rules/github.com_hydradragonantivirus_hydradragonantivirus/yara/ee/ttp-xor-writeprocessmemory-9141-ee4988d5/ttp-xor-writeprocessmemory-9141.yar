rule TTP_XOR_WriteProcessMemory_9141 {
  strings:
    $key_9141 = { c6 33 [2] f4 11 [2] f2 24 [2] dc 24 [2] e3 38 }

  condition:
    any of them
}