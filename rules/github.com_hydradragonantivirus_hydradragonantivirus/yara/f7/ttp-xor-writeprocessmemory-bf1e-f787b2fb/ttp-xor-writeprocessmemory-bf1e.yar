rule TTP_XOR_WriteProcessMemory_bf1e {
  strings:
    $key_bf1e = { e8 6c [2] da 4e [2] dc 7b [2] f2 7b [2] cd 67 }

  condition:
    any of them
}