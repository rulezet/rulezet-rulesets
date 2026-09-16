rule TTP_XOR_WriteProcessMemory_8090 {
  strings:
    $key_8090 = { d7 e2 [2] e5 c0 [2] e3 f5 [2] cd f5 [2] f2 e9 }

  condition:
    any of them
}