rule TTP_XOR_WriteProcessMemory_bf51 {
  strings:
    $key_bf51 = { e8 23 [2] da 01 [2] dc 34 [2] f2 34 [2] cd 28 }

  condition:
    any of them
}