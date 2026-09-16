rule TTP_XOR_WriteProcessMemory_bf65 {
  strings:
    $key_bf65 = { e8 17 [2] da 35 [2] dc 00 [2] f2 00 [2] cd 1c }

  condition:
    any of them
}