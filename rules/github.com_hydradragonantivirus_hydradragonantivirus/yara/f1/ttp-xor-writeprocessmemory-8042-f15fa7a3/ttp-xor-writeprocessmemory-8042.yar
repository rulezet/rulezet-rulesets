rule TTP_XOR_WriteProcessMemory_8042 {
  strings:
    $key_8042 = { d7 30 [2] e5 12 [2] e3 27 [2] cd 27 [2] f2 3b }

  condition:
    any of them
}