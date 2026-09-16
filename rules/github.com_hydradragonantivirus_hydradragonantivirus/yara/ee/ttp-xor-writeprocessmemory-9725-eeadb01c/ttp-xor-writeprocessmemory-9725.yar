rule TTP_XOR_WriteProcessMemory_9725 {
  strings:
    $key_9725 = { c0 57 [2] f2 75 [2] f4 40 [2] da 40 [2] e5 5c }

  condition:
    any of them
}