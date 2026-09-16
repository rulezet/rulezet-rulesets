rule TTP_XOR_WriteProcessMemory_a890 {
  strings:
    $key_a890 = { ff e2 [2] cd c0 [2] cb f5 [2] e5 f5 [2] da e9 }

  condition:
    any of them
}