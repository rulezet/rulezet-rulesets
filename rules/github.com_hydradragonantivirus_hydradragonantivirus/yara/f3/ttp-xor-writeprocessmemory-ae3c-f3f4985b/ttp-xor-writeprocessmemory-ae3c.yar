rule TTP_XOR_WriteProcessMemory_ae3c {
  strings:
    $key_ae3c = { f9 4e [2] cb 6c [2] cd 59 [2] e3 59 [2] dc 45 }

  condition:
    any of them
}