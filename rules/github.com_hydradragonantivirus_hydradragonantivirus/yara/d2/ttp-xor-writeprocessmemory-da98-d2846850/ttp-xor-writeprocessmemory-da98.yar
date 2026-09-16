rule TTP_XOR_WriteProcessMemory_da98 {
  strings:
    $key_da98 = { 8d ea [2] bf c8 [2] b9 fd [2] 97 fd [2] a8 e1 }

  condition:
    any of them
}