rule TTP_XOR_WriteProcessMemory_b6d4 {
  strings:
    $key_b6d4 = { e1 a6 [2] d3 84 [2] d5 b1 [2] fb b1 [2] c4 ad }

  condition:
    any of them
}