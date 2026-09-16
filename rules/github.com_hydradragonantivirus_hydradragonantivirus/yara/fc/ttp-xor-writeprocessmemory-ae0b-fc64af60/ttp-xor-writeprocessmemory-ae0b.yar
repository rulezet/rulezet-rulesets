rule TTP_XOR_WriteProcessMemory_ae0b {
  strings:
    $key_ae0b = { f9 79 [2] cb 5b [2] cd 6e [2] e3 6e [2] dc 72 }

  condition:
    any of them
}