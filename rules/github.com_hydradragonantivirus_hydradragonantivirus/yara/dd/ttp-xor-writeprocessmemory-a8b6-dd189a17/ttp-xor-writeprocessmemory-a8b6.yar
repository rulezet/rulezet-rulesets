rule TTP_XOR_WriteProcessMemory_a8b6 {
  strings:
    $key_a8b6 = { ff c4 [2] cd e6 [2] cb d3 [2] e5 d3 [2] da cf }

  condition:
    any of them
}