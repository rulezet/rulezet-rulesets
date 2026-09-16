rule TTP_XOR_WriteProcessMemory_bf90 {
  strings:
    $key_bf90 = { e8 e2 [2] da c0 [2] dc f5 [2] f2 f5 [2] cd e9 }

  condition:
    any of them
}