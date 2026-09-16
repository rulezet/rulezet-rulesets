rule TTP_XOR_WriteProcessMemory_fb98 {
  strings:
    $key_fb98 = { ac ea [2] 9e c8 [2] 98 fd [2] b6 fd [2] 89 e1 }

  condition:
    any of them
}