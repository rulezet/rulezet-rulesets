rule TTP_XOR_WriteProcessMemory_bf74 {
  strings:
    $key_bf74 = { e8 06 [2] da 24 [2] dc 11 [2] f2 11 [2] cd 0d }

  condition:
    any of them
}