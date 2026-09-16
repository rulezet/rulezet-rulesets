rule TTP_XOR_WriteProcessMemory_aea1 {
  strings:
    $key_aea1 = { f9 d3 [2] cb f1 [2] cd c4 [2] e3 c4 [2] dc d8 }

  condition:
    any of them
}