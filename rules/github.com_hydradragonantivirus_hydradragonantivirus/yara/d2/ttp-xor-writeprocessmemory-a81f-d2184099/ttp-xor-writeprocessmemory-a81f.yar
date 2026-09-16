rule TTP_XOR_WriteProcessMemory_a81f {
  strings:
    $key_a81f = { ff 6d [2] cd 4f [2] cb 7a [2] e5 7a [2] da 66 }

  condition:
    any of them
}