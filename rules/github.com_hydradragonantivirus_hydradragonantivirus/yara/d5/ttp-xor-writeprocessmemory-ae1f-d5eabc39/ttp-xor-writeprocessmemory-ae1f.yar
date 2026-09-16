rule TTP_XOR_WriteProcessMemory_ae1f {
  strings:
    $key_ae1f = { f9 6d [2] cb 4f [2] cd 7a [2] e3 7a [2] dc 66 }

  condition:
    any of them
}