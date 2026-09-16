rule TTP_XOR_WriteProcessMemory_22b2 {
  strings:
    $key_22b2 = { 75 c0 [2] 47 e2 [2] 41 d7 [2] 6f d7 [2] 50 cb }

  condition:
    any of them
}