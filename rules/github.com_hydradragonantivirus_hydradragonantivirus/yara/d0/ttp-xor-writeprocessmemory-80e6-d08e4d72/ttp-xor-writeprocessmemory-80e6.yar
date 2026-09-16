rule TTP_XOR_WriteProcessMemory_80e6 {
  strings:
    $key_80e6 = { d7 94 [2] e5 b6 [2] e3 83 [2] cd 83 [2] f2 9f }

  condition:
    any of them
}