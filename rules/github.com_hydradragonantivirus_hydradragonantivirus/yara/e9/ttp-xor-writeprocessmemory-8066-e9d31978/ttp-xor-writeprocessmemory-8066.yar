rule TTP_XOR_WriteProcessMemory_8066 {
  strings:
    $key_8066 = { d7 14 [2] e5 36 [2] e3 03 [2] cd 03 [2] f2 1f }

  condition:
    any of them
}