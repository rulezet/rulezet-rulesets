rule TTP_XOR_WriteProcessMemory_7298 {
  strings:
    $key_7298 = { 25 ea [2] 17 c8 [2] 11 fd [2] 3f fd [2] 00 e1 }

  condition:
    any of them
}