rule TTP_XOR_WriteProcessMemory_ae8c {
  strings:
    $key_ae8c = { f9 fe [2] cb dc [2] cd e9 [2] e3 e9 [2] dc f5 }

  condition:
    any of them
}