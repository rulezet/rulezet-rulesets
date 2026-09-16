rule TTP_XOR_WriteProcessMemory_21b2 {
  strings:
    $key_21b2 = { 76 c0 [2] 44 e2 [2] 42 d7 [2] 6c d7 [2] 53 cb }

  condition:
    any of them
}