rule TTP_XOR_WriteProcessMemory_bf79 {
  strings:
    $key_bf79 = { e8 0b [2] da 29 [2] dc 1c [2] f2 1c [2] cd 00 }

  condition:
    any of them
}