rule TTP_XOR_WriteProcessMemory_9146 {
  strings:
    $key_9146 = { c6 34 [2] f4 16 [2] f2 23 [2] dc 23 [2] e3 3f }

  condition:
    any of them
}