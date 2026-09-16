rule TTP_XOR_WriteProcessMemory_80a2 {
  strings:
    $key_80a2 = { d7 d0 [2] e5 f2 [2] e3 c7 [2] cd c7 [2] f2 db }

  condition:
    any of them
}