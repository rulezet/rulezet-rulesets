rule TTP_XOR_WriteProcessMemory_7498 {
  strings:
    $key_7498 = { 23 ea [2] 11 c8 [2] 17 fd [2] 39 fd [2] 06 e1 }

  condition:
    any of them
}