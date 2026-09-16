rule TTP_XOR_WriteProcessMemory_bfc1 {
  strings:
    $key_bfc1 = { e8 b3 [2] da 91 [2] dc a4 [2] f2 a4 [2] cd b8 }

  condition:
    any of them
}