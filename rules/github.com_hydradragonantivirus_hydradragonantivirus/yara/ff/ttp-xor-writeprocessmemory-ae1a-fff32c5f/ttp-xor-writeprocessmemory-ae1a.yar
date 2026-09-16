rule TTP_XOR_WriteProcessMemory_ae1a {
  strings:
    $key_ae1a = { f9 68 [2] cb 4a [2] cd 7f [2] e3 7f [2] dc 63 }

  condition:
    any of them
}