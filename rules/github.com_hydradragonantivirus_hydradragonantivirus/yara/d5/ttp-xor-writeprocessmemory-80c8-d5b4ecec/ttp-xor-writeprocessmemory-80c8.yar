rule TTP_XOR_WriteProcessMemory_80c8 {
  strings:
    $key_80c8 = { d7 ba [2] e5 98 [2] e3 ad [2] cd ad [2] f2 b1 }

  condition:
    any of them
}