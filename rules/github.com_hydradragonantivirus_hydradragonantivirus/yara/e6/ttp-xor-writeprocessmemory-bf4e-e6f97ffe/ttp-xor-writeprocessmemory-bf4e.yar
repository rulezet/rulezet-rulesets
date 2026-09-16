rule TTP_XOR_WriteProcessMemory_bf4e {
  strings:
    $key_bf4e = { e8 3c [2] da 1e [2] dc 2b [2] f2 2b [2] cd 37 }

  condition:
    any of them
}