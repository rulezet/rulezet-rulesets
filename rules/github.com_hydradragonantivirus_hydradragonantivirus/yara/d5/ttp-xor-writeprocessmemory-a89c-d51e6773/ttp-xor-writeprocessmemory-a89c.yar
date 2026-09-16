rule TTP_XOR_WriteProcessMemory_a89c {
  strings:
    $key_a89c = { ff ee [2] cd cc [2] cb f9 [2] e5 f9 [2] da e5 }

  condition:
    any of them
}