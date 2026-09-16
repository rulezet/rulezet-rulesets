rule TTP_XOR_WriteProcessMemory_ca98 {
  strings:
    $key_ca98 = { 9d ea [2] af c8 [2] a9 fd [2] 87 fd [2] b8 e1 }

  condition:
    any of them
}