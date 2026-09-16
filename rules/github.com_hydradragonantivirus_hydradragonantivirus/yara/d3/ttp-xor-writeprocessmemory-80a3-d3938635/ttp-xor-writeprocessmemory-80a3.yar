rule TTP_XOR_WriteProcessMemory_80a3 {
  strings:
    $key_80a3 = { d7 d1 [2] e5 f3 [2] e3 c6 [2] cd c6 [2] f2 da }

  condition:
    any of them
}