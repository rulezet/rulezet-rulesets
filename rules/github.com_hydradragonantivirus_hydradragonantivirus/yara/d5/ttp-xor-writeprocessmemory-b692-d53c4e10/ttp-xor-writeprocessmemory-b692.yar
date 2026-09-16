rule TTP_XOR_WriteProcessMemory_b692 {
  strings:
    $key_b692 = { e1 e0 [2] d3 c2 [2] d5 f7 [2] fb f7 [2] c4 eb }

  condition:
    any of them
}