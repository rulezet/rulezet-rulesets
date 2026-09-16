rule TTP_XOR_WriteProcessMemory_ae23 {
  strings:
    $key_ae23 = { f9 51 [2] cb 73 [2] cd 46 [2] e3 46 [2] dc 5a }

  condition:
    any of them
}