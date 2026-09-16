rule TTP_XOR_WriteProcessMemory_80a8 {
  strings:
    $key_80a8 = { d7 da [2] e5 f8 [2] e3 cd [2] cd cd [2] f2 d1 }

  condition:
    any of them
}