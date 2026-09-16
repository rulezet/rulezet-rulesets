rule TTP_XOR_WriteProcessMemory_9703 {
  strings:
    $key_9703 = { c0 71 [2] f2 53 [2] f4 66 [2] da 66 [2] e5 7a }

  condition:
    any of them
}