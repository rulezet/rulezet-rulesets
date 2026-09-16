rule TTP_XOR_WriteProcessMemory_ae39 {
  strings:
    $key_ae39 = { f9 4b [2] cb 69 [2] cd 5c [2] e3 5c [2] dc 40 }

  condition:
    any of them
}