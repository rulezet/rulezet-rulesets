rule TTP_XOR_WriteProcessMemory_ae43 {
  strings:
    $key_ae43 = { f9 31 [2] cb 13 [2] cd 26 [2] e3 26 [2] dc 3a }

  condition:
    any of them
}