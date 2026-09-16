rule TTP_XOR_WriteProcessMemory_8032 {
  strings:
    $key_8032 = { d7 40 [2] e5 62 [2] e3 57 [2] cd 57 [2] f2 4b }

  condition:
    any of them
}