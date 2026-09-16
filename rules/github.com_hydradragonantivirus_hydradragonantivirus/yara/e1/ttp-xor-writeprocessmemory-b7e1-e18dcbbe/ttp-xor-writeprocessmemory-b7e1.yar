rule TTP_XOR_WriteProcessMemory_b7e1 {
  strings:
    $key_b7e1 = { e0 93 [2] d2 b1 [2] d4 84 [2] fa 84 [2] c5 98 }

  condition:
    any of them
}