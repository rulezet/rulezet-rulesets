rule TTP_XOR_WriteProcessMemory_5598 {
  strings:
    $key_5598 = { 02 ea [2] 30 c8 [2] 36 fd [2] 18 fd [2] 27 e1 }

  condition:
    any of them
}