rule TTP_XOR_WriteProcessMemory_0a98 {
  strings:
    $key_0a98 = { 5d ea [2] 6f c8 [2] 69 fd [2] 47 fd [2] 78 e1 }

  condition:
    any of them
}