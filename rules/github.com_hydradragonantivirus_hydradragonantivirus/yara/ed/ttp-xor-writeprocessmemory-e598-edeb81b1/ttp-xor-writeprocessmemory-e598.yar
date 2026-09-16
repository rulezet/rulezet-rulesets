rule TTP_XOR_WriteProcessMemory_e598 {
  strings:
    $key_e598 = { b2 ea [2] 80 c8 [2] 86 fd [2] a8 fd [2] 97 e1 }

  condition:
    any of them
}