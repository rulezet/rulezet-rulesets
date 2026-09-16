rule TTP_XOR_WriteProcessMemory_d398 {
  strings:
    $key_d398 = { 84 ea [2] b6 c8 [2] b0 fd [2] 9e fd [2] a1 e1 }

  condition:
    any of them
}