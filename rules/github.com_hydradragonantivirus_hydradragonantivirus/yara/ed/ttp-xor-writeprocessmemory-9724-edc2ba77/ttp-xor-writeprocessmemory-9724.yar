rule TTP_XOR_WriteProcessMemory_9724 {
  strings:
    $key_9724 = { c0 56 [2] f2 74 [2] f4 41 [2] da 41 [2] e5 5d }

  condition:
    any of them
}