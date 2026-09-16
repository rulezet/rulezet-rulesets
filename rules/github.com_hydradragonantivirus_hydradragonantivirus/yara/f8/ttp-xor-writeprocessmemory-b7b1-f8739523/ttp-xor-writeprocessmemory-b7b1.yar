rule TTP_XOR_WriteProcessMemory_b7b1 {
  strings:
    $key_b7b1 = { e0 c3 [2] d2 e1 [2] d4 d4 [2] fa d4 [2] c5 c8 }

  condition:
    any of them
}