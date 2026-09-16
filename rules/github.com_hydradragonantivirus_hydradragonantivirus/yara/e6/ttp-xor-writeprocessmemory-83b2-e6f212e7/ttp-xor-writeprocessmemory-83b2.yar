rule TTP_XOR_WriteProcessMemory_83b2 {
  strings:
    $key_83b2 = { d4 c0 [2] e6 e2 [2] e0 d7 [2] ce d7 [2] f1 cb }

  condition:
    any of them
}