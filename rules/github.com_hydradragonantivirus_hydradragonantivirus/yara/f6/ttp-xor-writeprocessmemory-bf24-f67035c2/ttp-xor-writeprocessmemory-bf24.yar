rule TTP_XOR_WriteProcessMemory_bf24 {
  strings:
    $key_bf24 = { e8 56 [2] da 74 [2] dc 41 [2] f2 41 [2] cd 5d }

  condition:
    any of them
}