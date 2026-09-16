rule TTP_XOR_WriteProcessMemory_aea4 {
  strings:
    $key_aea4 = { f9 d6 [2] cb f4 [2] cd c1 [2] e3 c1 [2] dc dd }

  condition:
    any of them
}