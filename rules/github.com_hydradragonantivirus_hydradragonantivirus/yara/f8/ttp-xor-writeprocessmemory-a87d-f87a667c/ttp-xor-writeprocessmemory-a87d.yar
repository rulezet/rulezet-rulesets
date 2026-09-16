rule TTP_XOR_WriteProcessMemory_a87d {
  strings:
    $key_a87d = { ff 0f [2] cd 2d [2] cb 18 [2] e5 18 [2] da 04 }

  condition:
    any of them
}