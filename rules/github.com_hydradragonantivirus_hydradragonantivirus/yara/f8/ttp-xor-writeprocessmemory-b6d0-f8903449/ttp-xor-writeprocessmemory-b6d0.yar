rule TTP_XOR_WriteProcessMemory_b6d0 {
  strings:
    $key_b6d0 = { e1 a2 [2] d3 80 [2] d5 b5 [2] fb b5 [2] c4 a9 }

  condition:
    any of them
}