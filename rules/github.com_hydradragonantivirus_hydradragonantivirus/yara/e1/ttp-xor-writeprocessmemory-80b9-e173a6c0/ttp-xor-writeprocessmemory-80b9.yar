rule TTP_XOR_WriteProcessMemory_80b9 {
  strings:
    $key_80b9 = { d7 cb [2] e5 e9 [2] e3 dc [2] cd dc [2] f2 c0 }

  condition:
    any of them
}