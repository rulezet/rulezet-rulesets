rule TTP_XOR_WriteProcessMemory_ae5e {
  strings:
    $key_ae5e = { f9 2c [2] cb 0e [2] cd 3b [2] e3 3b [2] dc 27 }

  condition:
    any of them
}