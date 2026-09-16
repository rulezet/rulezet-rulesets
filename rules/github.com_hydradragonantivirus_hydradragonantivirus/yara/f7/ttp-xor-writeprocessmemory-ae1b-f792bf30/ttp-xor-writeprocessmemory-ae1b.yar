rule TTP_XOR_WriteProcessMemory_ae1b {
  strings:
    $key_ae1b = { f9 69 [2] cb 4b [2] cd 7e [2] e3 7e [2] dc 62 }

  condition:
    any of them
}