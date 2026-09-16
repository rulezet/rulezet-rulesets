rule TTP_XOR_WriteProcessMemory_aeb3 {
  strings:
    $key_aeb3 = { f9 c1 [2] cb e3 [2] cd d6 [2] e3 d6 [2] dc ca }

  condition:
    any of them
}