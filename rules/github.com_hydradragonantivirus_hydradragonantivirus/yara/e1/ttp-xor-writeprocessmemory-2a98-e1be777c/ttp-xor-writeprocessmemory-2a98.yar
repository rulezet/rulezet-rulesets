rule TTP_XOR_WriteProcessMemory_2a98 {
  strings:
    $key_2a98 = { 7d ea [2] 4f c8 [2] 49 fd [2] 67 fd [2] 58 e1 }

  condition:
    any of them
}