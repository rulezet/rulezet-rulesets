rule TTP_XOR_WriteProcessMemory_9704 {
  strings:
    $key_9704 = { c0 76 [2] f2 54 [2] f4 61 [2] da 61 [2] e5 7d }

  condition:
    any of them
}