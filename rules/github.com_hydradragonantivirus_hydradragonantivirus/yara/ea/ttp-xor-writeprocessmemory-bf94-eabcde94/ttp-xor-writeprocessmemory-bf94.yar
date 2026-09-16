rule TTP_XOR_WriteProcessMemory_bf94 {
  strings:
    $key_bf94 = { e8 e6 [2] da c4 [2] dc f1 [2] f2 f1 [2] cd ed }

  condition:
    any of them
}