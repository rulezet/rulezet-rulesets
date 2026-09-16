rule TTP_XOR_WriteProcessMemory_80b1 {
  strings:
    $key_80b1 = { d7 c3 [2] e5 e1 [2] e3 d4 [2] cd d4 [2] f2 c8 }

  condition:
    any of them
}