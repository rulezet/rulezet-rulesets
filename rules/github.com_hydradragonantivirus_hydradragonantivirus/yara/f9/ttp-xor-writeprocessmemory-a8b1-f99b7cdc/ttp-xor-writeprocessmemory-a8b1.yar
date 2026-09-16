rule TTP_XOR_WriteProcessMemory_a8b1 {
  strings:
    $key_a8b1 = { ff c3 [2] cd e1 [2] cb d4 [2] e5 d4 [2] da c8 }

  condition:
    any of them
}