rule TTP_XOR_WriteProcessMemory_ae79 {
  strings:
    $key_ae79 = { f9 0b [2] cb 29 [2] cd 1c [2] e3 1c [2] dc 00 }

  condition:
    any of them
}