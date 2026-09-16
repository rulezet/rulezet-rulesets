rule TTP_XOR_WriteProcessMemory_ae2c {
  strings:
    $key_ae2c = { f9 5e [2] cb 7c [2] cd 49 [2] e3 49 [2] dc 55 }

  condition:
    any of them
}