rule TTP_XOR_WriteProcessMemory_b6a6 {
  strings:
    $key_b6a6 = { e1 d4 [2] d3 f6 [2] d5 c3 [2] fb c3 [2] c4 df }

  condition:
    any of them
}