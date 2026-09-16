rule TTP_XOR_WriteProcessMemory_8054 {
  strings:
    $key_8054 = { d7 26 [2] e5 04 [2] e3 31 [2] cd 31 [2] f2 2d }

  condition:
    any of them
}