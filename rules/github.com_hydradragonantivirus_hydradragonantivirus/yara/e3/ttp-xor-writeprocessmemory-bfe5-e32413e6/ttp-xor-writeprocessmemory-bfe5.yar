rule TTP_XOR_WriteProcessMemory_bfe5 {
  strings:
    $key_bfe5 = { e8 97 [2] da b5 [2] dc 80 [2] f2 80 [2] cd 9c }

  condition:
    any of them
}