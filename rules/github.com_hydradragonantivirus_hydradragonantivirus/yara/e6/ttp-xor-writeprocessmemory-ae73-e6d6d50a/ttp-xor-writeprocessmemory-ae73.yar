rule TTP_XOR_WriteProcessMemory_ae73 {
  strings:
    $key_ae73 = { f9 01 [2] cb 23 [2] cd 16 [2] e3 16 [2] dc 0a }

  condition:
    any of them
}