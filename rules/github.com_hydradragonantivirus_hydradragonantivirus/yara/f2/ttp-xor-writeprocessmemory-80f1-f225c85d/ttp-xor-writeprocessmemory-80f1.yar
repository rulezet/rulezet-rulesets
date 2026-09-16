rule TTP_XOR_WriteProcessMemory_80f1 {
  strings:
    $key_80f1 = { d7 83 [2] e5 a1 [2] e3 94 [2] cd 94 [2] f2 88 }

  condition:
    any of them
}