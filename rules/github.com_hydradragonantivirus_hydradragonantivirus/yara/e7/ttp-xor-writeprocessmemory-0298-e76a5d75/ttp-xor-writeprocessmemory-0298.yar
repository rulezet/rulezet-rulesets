rule TTP_XOR_WriteProcessMemory_0298 {
  strings:
    $key_0298 = { 55 ea [2] 67 c8 [2] 61 fd [2] 4f fd [2] 70 e1 }

  condition:
    any of them
}