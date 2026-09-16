rule TTP_XOR_WriteProcessMemory_ae5f {
  strings:
    $key_ae5f = { f9 2d [2] cb 0f [2] cd 3a [2] e3 3a [2] dc 26 }

  condition:
    any of them
}