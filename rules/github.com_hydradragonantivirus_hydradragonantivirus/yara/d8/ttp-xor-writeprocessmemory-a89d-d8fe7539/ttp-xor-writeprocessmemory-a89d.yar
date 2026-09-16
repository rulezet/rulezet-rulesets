rule TTP_XOR_WriteProcessMemory_a89d {
  strings:
    $key_a89d = { ff ef [2] cd cd [2] cb f8 [2] e5 f8 [2] da e4 }

  condition:
    any of them
}