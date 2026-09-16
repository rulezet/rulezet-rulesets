rule TTP_XOR_WriteProcessMemory_ae45 {
  strings:
    $key_ae45 = { f9 37 [2] cb 15 [2] cd 20 [2] e3 20 [2] dc 3c }

  condition:
    any of them
}