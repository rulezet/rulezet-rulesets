rule TTP_XOR_WriteProcessMemory_a852 {
  strings:
    $key_a852 = { ff 20 [2] cd 02 [2] cb 37 [2] e5 37 [2] da 2b }

  condition:
    any of them
}