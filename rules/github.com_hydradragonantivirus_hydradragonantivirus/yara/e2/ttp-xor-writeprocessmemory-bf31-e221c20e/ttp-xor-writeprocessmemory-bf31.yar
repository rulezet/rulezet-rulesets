rule TTP_XOR_WriteProcessMemory_bf31 {
  strings:
    $key_bf31 = { e8 43 [2] da 61 [2] dc 54 [2] f2 54 [2] cd 48 }

  condition:
    any of them
}