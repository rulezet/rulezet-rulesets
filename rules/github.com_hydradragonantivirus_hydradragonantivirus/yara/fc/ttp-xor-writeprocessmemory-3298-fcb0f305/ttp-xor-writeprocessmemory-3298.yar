rule TTP_XOR_WriteProcessMemory_3298 {
  strings:
    $key_3298 = { 65 ea [2] 57 c8 [2] 51 fd [2] 7f fd [2] 40 e1 }

  condition:
    any of them
}