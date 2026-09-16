rule TTP_XOR_WriteProcessMemory_aea3 {
  strings:
    $key_aea3 = { f9 d1 [2] cb f3 [2] cd c6 [2] e3 c6 [2] dc da }

  condition:
    any of them
}