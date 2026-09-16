rule TTP_XOR_WriteProcessMemory_9731 {
  strings:
    $key_9731 = { c0 43 [2] f2 61 [2] f4 54 [2] da 54 [2] e5 48 }

  condition:
    any of them
}