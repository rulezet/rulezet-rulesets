rule TTP_XOR_WriteProcessMemory_bf03 {
  strings:
    $key_bf03 = { e8 71 [2] da 53 [2] dc 66 [2] f2 66 [2] cd 7a }

  condition:
    any of them
}