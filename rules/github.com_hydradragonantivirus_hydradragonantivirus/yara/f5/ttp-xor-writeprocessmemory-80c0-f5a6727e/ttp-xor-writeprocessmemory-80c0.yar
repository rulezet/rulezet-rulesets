rule TTP_XOR_WriteProcessMemory_80c0 {
  strings:
    $key_80c0 = { d7 b2 [2] e5 90 [2] e3 a5 [2] cd a5 [2] f2 b9 }

  condition:
    any of them
}