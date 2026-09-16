rule TTP_XOR_WriteProcessMemory_b3e1 {
  strings:
    $key_b3e1 = { e4 93 [2] d6 b1 [2] d0 84 [2] fe 84 [2] c1 98 }

  condition:
    any of them
}