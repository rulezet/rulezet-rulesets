rule TTP_XOR_WriteProcessMemory_bf6c {
  strings:
    $key_bf6c = { e8 1e [2] da 3c [2] dc 09 [2] f2 09 [2] cd 15 }

  condition:
    any of them
}