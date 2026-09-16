rule TTP_XOR_WriteProcessMemory_bfc3 {
  strings:
    $key_bfc3 = { e8 b1 [2] da 93 [2] dc a6 [2] f2 a6 [2] cd ba }

  condition:
    any of them
}