rule TTP_XOR_WriteProcessMemory_ae82 {
  strings:
    $key_ae82 = { f9 f0 [2] cb d2 [2] cd e7 [2] e3 e7 [2] dc fb }

  condition:
    any of them
}