rule TTP_XOR_WriteProcessMemory_bf26 {
  strings:
    $key_bf26 = { e8 54 [2] da 76 [2] dc 43 [2] f2 43 [2] cd 5f }

  condition:
    any of them
}