rule TTP_XOR_WriteProcessMemory_67b2 {
  strings:
    $key_67b2 = { 30 c0 [2] 02 e2 [2] 04 d7 [2] 2a d7 [2] 15 cb }

  condition:
    any of them
}