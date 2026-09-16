rule TTP_XOR_WriteProcessMemory_80b2 {
  strings:
    $key_80b2 = { d7 c0 [2] e5 e2 [2] e3 d7 [2] cd d7 [2] f2 cb }

  condition:
    any of them
}