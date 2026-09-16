rule TTP_XOR_WriteProcessMemory_23b1 {
  strings:
    $key_23b1 = { 74 c3 [2] 46 e1 [2] 40 d4 [2] 6e d4 [2] 51 c8 }

  condition:
    any of them
}