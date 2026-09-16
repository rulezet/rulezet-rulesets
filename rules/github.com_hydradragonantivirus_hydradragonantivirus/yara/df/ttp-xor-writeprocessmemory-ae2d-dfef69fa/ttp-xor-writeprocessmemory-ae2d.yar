rule TTP_XOR_WriteProcessMemory_ae2d {
  strings:
    $key_ae2d = { f9 5f [2] cb 7d [2] cd 48 [2] e3 48 [2] dc 54 }

  condition:
    any of them
}