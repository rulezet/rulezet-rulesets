rule TTP_XOR_WriteProcessMemory_a8aa {
  strings:
    $key_a8aa = { ff d8 [2] cd fa [2] cb cf [2] e5 cf [2] da d3 }

  condition:
    any of them
}