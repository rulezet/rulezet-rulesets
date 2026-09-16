rule TTP_XOR_WriteProcessMemory_bfd2 {
  strings:
    $key_bfd2 = { e8 a0 [2] da 82 [2] dc b7 [2] f2 b7 [2] cd ab }

  condition:
    any of them
}