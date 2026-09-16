rule TTP_XOR_WriteProcessMemory_a87f {
  strings:
    $key_a87f = { ff 0d [2] cd 2f [2] cb 1a [2] e5 1a [2] da 06 }

  condition:
    any of them
}