rule TTP_XOR_WriteProcessMemory_ae08 {
  strings:
    $key_ae08 = { f9 7a [2] cb 58 [2] cd 6d [2] e3 6d [2] dc 71 }

  condition:
    any of them
}