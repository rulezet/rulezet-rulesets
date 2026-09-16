rule TTP_XOR_WriteProcessMemory_ae60 {
  strings:
    $key_ae60 = { f9 12 [2] cb 30 [2] cd 05 [2] e3 05 [2] dc 19 }

  condition:
    any of them
}