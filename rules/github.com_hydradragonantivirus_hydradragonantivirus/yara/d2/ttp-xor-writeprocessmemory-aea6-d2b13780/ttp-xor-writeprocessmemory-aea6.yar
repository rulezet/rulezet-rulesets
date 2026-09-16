rule TTP_XOR_WriteProcessMemory_aea6 {
  strings:
    $key_aea6 = { f9 d4 [2] cb f6 [2] cd c3 [2] e3 c3 [2] dc df }

  condition:
    any of them
}