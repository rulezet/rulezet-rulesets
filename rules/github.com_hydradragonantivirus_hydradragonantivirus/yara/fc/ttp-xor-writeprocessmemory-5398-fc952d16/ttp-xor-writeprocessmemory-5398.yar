rule TTP_XOR_WriteProcessMemory_5398 {
  strings:
    $key_5398 = { 04 ea [2] 36 c8 [2] 30 fd [2] 1e fd [2] 21 e1 }

  condition:
    any of them
}