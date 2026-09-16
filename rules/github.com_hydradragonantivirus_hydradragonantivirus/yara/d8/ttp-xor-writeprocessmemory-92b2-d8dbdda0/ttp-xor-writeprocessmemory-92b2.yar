rule TTP_XOR_WriteProcessMemory_92b2 {
  strings:
    $key_92b2 = { c5 c0 [2] f7 e2 [2] f1 d7 [2] df d7 [2] e0 cb }

  condition:
    any of them
}