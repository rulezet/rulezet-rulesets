rule TTP_XOR_WriteProcessMemory_9741 {
  strings:
    $key_9741 = { c0 33 [2] f2 11 [2] f4 24 [2] da 24 [2] e5 38 }

  condition:
    any of them
}