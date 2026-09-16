rule TTP_XOR_WriteProcessMemory_b6a7 {
  strings:
    $key_b6a7 = { e1 d5 [2] d3 f7 [2] d5 c2 [2] fb c2 [2] c4 de }

  condition:
    any of them
}