rule TTP_XOR_WriteProcessMemory_80f6 {
  strings:
    $key_80f6 = { d7 84 [2] e5 a6 [2] e3 93 [2] cd 93 [2] f2 8f }

  condition:
    any of them
}