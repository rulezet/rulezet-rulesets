rule TTP_XOR_WriteProcessMemory_aefd {
  strings:
    $key_aefd = { f9 8f [2] cb ad [2] cd 98 [2] e3 98 [2] dc 84 }

  condition:
    any of them
}