rule TTP_XOR_WriteProcessMemory_ae7f {
  strings:
    $key_ae7f = { f9 0d [2] cb 2f [2] cd 1a [2] e3 1a [2] dc 06 }

  condition:
    any of them
}