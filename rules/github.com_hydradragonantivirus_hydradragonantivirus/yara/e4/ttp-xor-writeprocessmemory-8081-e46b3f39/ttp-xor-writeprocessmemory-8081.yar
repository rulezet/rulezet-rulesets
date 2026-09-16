rule TTP_XOR_WriteProcessMemory_8081 {
  strings:
    $key_8081 = { d7 f3 [2] e5 d1 [2] e3 e4 [2] cd e4 [2] f2 f8 }

  condition:
    any of them
}