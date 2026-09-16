rule TTP_XOR_WriteProcessMemory_4098 {
  strings:
    $key_4098 = { 17 ea [2] 25 c8 [2] 23 fd [2] 0d fd [2] 32 e1 }

  condition:
    any of them
}