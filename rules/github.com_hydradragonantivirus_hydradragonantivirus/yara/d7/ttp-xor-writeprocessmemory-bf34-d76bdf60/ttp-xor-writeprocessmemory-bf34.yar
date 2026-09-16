rule TTP_XOR_WriteProcessMemory_bf34 {
  strings:
    $key_bf34 = { e8 46 [2] da 64 [2] dc 51 [2] f2 51 [2] cd 4d }

  condition:
    any of them
}