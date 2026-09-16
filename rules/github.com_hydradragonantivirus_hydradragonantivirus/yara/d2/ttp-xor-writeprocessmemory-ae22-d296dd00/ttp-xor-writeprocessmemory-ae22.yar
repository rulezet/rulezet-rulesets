rule TTP_XOR_WriteProcessMemory_ae22 {
  strings:
    $key_ae22 = { f9 50 [2] cb 72 [2] cd 47 [2] e3 47 [2] dc 5b }

  condition:
    any of them
}