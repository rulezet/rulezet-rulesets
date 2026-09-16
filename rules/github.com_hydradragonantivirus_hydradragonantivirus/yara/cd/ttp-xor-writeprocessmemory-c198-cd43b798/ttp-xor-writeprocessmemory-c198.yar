rule TTP_XOR_WriteProcessMemory_c198 {
  strings:
    $key_c198 = { 96 ea [2] a4 c8 [2] a2 fd [2] 8c fd [2] b3 e1 }

  condition:
    any of them
}