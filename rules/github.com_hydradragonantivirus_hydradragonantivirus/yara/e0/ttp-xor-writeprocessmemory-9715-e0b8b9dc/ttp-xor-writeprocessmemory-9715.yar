rule TTP_XOR_WriteProcessMemory_9715 {
  strings:
    $key_9715 = { c0 67 [2] f2 45 [2] f4 70 [2] da 70 [2] e5 6c }

  condition:
    any of them
}