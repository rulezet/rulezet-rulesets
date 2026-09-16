rule TTP_XOR_WriteProcessMemory_80d2 {
  strings:
    $key_80d2 = { d7 a0 [2] e5 82 [2] e3 b7 [2] cd b7 [2] f2 ab }

  condition:
    any of them
}