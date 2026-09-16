rule TTP_XOR_WriteProcessMemory_3a98 {
  strings:
    $key_3a98 = { 6d ea [2] 5f c8 [2] 59 fd [2] 77 fd [2] 48 e1 }

  condition:
    any of them
}