rule TTP_XOR_WriteProcessMemory_b6d6 {
  strings:
    $key_b6d6 = { e1 a4 [2] d3 86 [2] d5 b3 [2] fb b3 [2] c4 af }

  condition:
    any of them
}