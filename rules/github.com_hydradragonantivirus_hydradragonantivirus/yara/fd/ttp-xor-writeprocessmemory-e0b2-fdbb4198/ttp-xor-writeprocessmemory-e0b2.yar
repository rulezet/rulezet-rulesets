rule TTP_XOR_WriteProcessMemory_e0b2 {
  strings:
    $key_e0b2 = { b7 c0 [2] 85 e2 [2] 83 d7 [2] ad d7 [2] 92 cb }

  condition:
    any of them
}