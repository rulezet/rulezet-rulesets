rule TTP_XOR_WriteProcessMemory_8098 {
  strings:
    $key_8098 = { d7 ea [2] e5 c8 [2] e3 fd [2] cd fd [2] f2 e1 }

  condition:
    any of them
}