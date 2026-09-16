rule TTP_XOR_WriteProcessMemory_8043 {
  strings:
    $key_8043 = { d7 31 [2] e5 13 [2] e3 26 [2] cd 26 [2] f2 3a }

  condition:
    any of them
}