rule TTP_XOR_WriteProcessMemory_ae6f {
  strings:
    $key_ae6f = { f9 1d [2] cb 3f [2] cd 0a [2] e3 0a [2] dc 16 }

  condition:
    any of them
}