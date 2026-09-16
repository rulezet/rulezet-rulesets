rule TTP_XOR_WriteProcessMemory_bfab {
  strings:
    $key_bfab = { e8 d9 [2] da fb [2] dc ce [2] f2 ce [2] cd d2 }

  condition:
    any of them
}