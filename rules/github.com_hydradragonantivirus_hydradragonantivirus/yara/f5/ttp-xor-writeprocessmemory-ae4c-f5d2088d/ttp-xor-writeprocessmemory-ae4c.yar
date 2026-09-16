rule TTP_XOR_WriteProcessMemory_ae4c {
  strings:
    $key_ae4c = { f9 3e [2] cb 1c [2] cd 29 [2] e3 29 [2] dc 35 }

  condition:
    any of them
}