rule TTP_XOR_WriteProcessMemory_ae70 {
  strings:
    $key_ae70 = { f9 02 [2] cb 20 [2] cd 15 [2] e3 15 [2] dc 09 }

  condition:
    any of them
}