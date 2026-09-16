rule TTP_XOR_WriteProcessMemory_a8ac {
  strings:
    $key_a8ac = { ff de [2] cd fc [2] cb c9 [2] e5 c9 [2] da d5 }

  condition:
    any of them
}