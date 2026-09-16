rule TTP_XOR_WriteProcessMemory_bf1b {
  strings:
    $key_bf1b = { e8 69 [2] da 4b [2] dc 7e [2] f2 7e [2] cd 62 }

  condition:
    any of them
}