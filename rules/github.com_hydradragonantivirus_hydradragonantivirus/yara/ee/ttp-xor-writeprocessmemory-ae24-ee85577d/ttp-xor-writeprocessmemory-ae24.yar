rule TTP_XOR_WriteProcessMemory_ae24 {
  strings:
    $key_ae24 = { f9 56 [2] cb 74 [2] cd 41 [2] e3 41 [2] dc 5d }

  condition:
    any of them
}