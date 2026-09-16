rule TTP_XOR_WriteProcessMemory_42b2 {
  strings:
    $key_42b2 = { 15 c0 [2] 27 e2 [2] 21 d7 [2] 0f d7 [2] 30 cb }

  condition:
    any of them
}