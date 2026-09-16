rule TTP_XOR_WriteProcessMemory_a8ef {
  strings:
    $key_a8ef = { ff 9d [2] cd bf [2] cb 8a [2] e5 8a [2] da 96 }

  condition:
    any of them
}