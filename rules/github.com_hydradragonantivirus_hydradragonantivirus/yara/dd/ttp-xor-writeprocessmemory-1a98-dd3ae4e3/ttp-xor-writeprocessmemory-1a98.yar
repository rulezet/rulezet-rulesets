rule TTP_XOR_WriteProcessMemory_1a98 {
  strings:
    $key_1a98 = { 4d ea [2] 7f c8 [2] 79 fd [2] 57 fd [2] 68 e1 }

  condition:
    any of them
}