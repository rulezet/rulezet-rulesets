rule TTP_XOR_WriteProcessMemory_b6e1 {
  strings:
    $key_b6e1 = { e1 93 [2] d3 b1 [2] d5 84 [2] fb 84 [2] c4 98 }

  condition:
    any of them
}