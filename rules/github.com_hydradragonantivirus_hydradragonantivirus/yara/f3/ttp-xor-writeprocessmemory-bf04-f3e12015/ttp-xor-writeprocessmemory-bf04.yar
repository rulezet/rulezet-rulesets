rule TTP_XOR_WriteProcessMemory_bf04 {
  strings:
    $key_bf04 = { e8 76 [2] da 54 [2] dc 61 [2] f2 61 [2] cd 7d }

  condition:
    any of them
}