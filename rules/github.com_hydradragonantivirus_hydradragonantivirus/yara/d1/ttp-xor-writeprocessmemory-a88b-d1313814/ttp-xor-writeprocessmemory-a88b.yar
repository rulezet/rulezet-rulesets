rule TTP_XOR_WriteProcessMemory_a88b {
  strings:
    $key_a88b = { ff f9 [2] cd db [2] cb ee [2] e5 ee [2] da f2 }

  condition:
    any of them
}