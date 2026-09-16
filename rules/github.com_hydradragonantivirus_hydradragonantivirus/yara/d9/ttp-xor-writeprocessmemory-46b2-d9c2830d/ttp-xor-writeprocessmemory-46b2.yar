rule TTP_XOR_WriteProcessMemory_46b2 {
  strings:
    $key_46b2 = { 11 c0 [2] 23 e2 [2] 25 d7 [2] 0b d7 [2] 34 cb }

  condition:
    any of them
}