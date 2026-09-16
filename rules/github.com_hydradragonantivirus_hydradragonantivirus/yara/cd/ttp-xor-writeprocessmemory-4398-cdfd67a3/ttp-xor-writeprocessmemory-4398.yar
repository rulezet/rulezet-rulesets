rule TTP_XOR_WriteProcessMemory_4398 {
  strings:
    $key_4398 = { 14 ea [2] 26 c8 [2] 20 fd [2] 0e fd [2] 31 e1 }

  condition:
    any of them
}