rule TTP_XOR_WriteProcessMemory_bfcd {
  strings:
    $key_bfcd = { e8 bf [2] da 9d [2] dc a8 [2] f2 a8 [2] cd b4 }

  condition:
    any of them
}