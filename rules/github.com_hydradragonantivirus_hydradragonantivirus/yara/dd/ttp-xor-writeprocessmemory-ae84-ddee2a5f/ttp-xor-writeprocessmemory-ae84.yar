rule TTP_XOR_WriteProcessMemory_ae84 {
  strings:
    $key_ae84 = { f9 f6 [2] cb d4 [2] cd e1 [2] e3 e1 [2] dc fd }

  condition:
    any of them
}