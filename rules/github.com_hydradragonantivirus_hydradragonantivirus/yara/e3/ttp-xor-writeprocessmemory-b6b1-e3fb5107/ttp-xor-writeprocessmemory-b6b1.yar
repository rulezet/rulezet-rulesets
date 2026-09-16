rule TTP_XOR_WriteProcessMemory_b6b1 {
  strings:
    $key_b6b1 = { e1 c3 [2] d3 e1 [2] d5 d4 [2] fb d4 [2] c4 c8 }

  condition:
    any of them
}