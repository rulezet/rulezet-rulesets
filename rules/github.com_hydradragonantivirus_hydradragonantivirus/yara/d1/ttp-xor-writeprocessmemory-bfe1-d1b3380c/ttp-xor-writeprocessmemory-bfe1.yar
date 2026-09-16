rule TTP_XOR_WriteProcessMemory_bfe1 {
  strings:
    $key_bfe1 = { e8 93 [2] da b1 [2] dc 84 [2] f2 84 [2] cd 98 }

  condition:
    any of them
}