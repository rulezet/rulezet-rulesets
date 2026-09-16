rule TTP_XOR_WriteProcessMemory_bf72 {
  strings:
    $key_bf72 = { e8 00 [2] da 22 [2] dc 17 [2] f2 17 [2] cd 0b }

  condition:
    any of them
}