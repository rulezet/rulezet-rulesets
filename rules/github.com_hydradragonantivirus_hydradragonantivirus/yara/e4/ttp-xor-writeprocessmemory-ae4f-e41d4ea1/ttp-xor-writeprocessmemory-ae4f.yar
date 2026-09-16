rule TTP_XOR_WriteProcessMemory_ae4f {
  strings:
    $key_ae4f = { f9 3d [2] cb 1f [2] cd 2a [2] e3 2a [2] dc 36 }

  condition:
    any of them
}