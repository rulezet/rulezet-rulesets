rule TTP_XOR_WriteProcessMemory_b68c {
  strings:
    $key_b68c = { e1 fe [2] d3 dc [2] d5 e9 [2] fb e9 [2] c4 f5 }

  condition:
    any of them
}