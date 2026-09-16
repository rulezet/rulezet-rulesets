rule TTP_XOR_WriteProcessMemory_aea2 {
  strings:
    $key_aea2 = { f9 d0 [2] cb f2 [2] cd c7 [2] e3 c7 [2] dc db }

  condition:
    any of them
}