rule TTP_XOR_WriteProcessMemory_e581 {
  strings:
    $key_e581 = { b2 f3 [2] 80 d1 [2] 86 e4 [2] a8 e4 [2] 97 f8 }

  condition:
    any of them
}