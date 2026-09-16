rule TTP_XOR_WriteProcessMemory_ae7b {
  strings:
    $key_ae7b = { f9 09 [2] cb 2b [2] cd 1e [2] e3 1e [2] dc 02 }

  condition:
    any of them
}