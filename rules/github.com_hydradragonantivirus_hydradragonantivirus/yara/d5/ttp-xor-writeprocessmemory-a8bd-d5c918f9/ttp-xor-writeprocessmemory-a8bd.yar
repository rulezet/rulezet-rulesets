rule TTP_XOR_WriteProcessMemory_a8bd {
  strings:
    $key_a8bd = { ff cf [2] cd ed [2] cb d8 [2] e5 d8 [2] da c4 }

  condition:
    any of them
}