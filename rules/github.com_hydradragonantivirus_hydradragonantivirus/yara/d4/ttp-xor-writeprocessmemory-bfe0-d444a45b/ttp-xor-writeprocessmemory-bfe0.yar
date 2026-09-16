rule TTP_XOR_WriteProcessMemory_bfe0 {
  strings:
    $key_bfe0 = { e8 92 [2] da b0 [2] dc 85 [2] f2 85 [2] cd 99 }

  condition:
    any of them
}