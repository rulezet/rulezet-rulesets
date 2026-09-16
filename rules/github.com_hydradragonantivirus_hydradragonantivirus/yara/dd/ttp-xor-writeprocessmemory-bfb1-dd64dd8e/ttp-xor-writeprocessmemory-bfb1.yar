rule TTP_XOR_WriteProcessMemory_bfb1 {
  strings:
    $key_bfb1 = { e8 c3 [2] da e1 [2] dc d4 [2] f2 d4 [2] cd c8 }

  condition:
    any of them
}