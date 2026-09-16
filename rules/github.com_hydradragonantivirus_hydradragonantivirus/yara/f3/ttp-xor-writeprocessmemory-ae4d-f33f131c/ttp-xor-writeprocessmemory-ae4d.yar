rule TTP_XOR_WriteProcessMemory_ae4d {
  strings:
    $key_ae4d = { f9 3f [2] cb 1d [2] cd 28 [2] e3 28 [2] dc 34 }

  condition:
    any of them
}