rule TTP_XOR_WriteProcessMemory_8030 {
  strings:
    $key_8030 = { d7 42 [2] e5 60 [2] e3 55 [2] cd 55 [2] f2 49 }

  condition:
    any of them
}