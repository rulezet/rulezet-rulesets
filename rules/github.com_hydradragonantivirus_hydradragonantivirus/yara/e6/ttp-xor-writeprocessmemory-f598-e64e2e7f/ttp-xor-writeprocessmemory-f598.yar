rule TTP_XOR_WriteProcessMemory_f598 {
  strings:
    $key_f598 = { a2 ea [2] 90 c8 [2] 96 fd [2] b8 fd [2] 87 e1 }

  condition:
    any of them
}