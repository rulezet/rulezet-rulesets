rule TTP_XOR_WriteProcessMemory_bfc0 {
  strings:
    $key_bfc0 = { e8 b2 [2] da 90 [2] dc a5 [2] f2 a5 [2] cd b9 }

  condition:
    any of them
}