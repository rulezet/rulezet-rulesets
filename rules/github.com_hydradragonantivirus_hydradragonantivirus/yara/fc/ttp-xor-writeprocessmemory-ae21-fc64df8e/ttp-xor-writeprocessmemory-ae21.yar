rule TTP_XOR_WriteProcessMemory_ae21 {
  strings:
    $key_ae21 = { f9 53 [2] cb 71 [2] cd 44 [2] e3 44 [2] dc 58 }

  condition:
    any of them
}