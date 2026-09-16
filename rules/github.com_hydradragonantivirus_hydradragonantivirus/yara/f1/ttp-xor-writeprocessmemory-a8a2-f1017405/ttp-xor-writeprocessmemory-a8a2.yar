rule TTP_XOR_WriteProcessMemory_a8a2 {
  strings:
    $key_a8a2 = { ff d0 [2] cd f2 [2] cb c7 [2] e5 c7 [2] da db }

  condition:
    any of them
}