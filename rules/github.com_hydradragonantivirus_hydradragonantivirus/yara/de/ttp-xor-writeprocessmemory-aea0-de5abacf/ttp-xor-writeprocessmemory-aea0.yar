rule TTP_XOR_WriteProcessMemory_aea0 {
  strings:
    $key_aea0 = { f9 d2 [2] cb f0 [2] cd c5 [2] e3 c5 [2] dc d9 }

  condition:
    any of them
}