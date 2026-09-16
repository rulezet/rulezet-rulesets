rule TTP_XOR_WriteProcessMemory_ae5b {
  strings:
    $key_ae5b = { f9 29 [2] cb 0b [2] cd 3e [2] e3 3e [2] dc 22 }

  condition:
    any of them
}