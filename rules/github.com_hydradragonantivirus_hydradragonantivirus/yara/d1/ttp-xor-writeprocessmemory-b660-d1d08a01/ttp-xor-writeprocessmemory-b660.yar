rule TTP_XOR_WriteProcessMemory_b660 {
  strings:
    $key_b660 = { e1 12 [2] d3 30 [2] d5 05 [2] fb 05 [2] c4 19 }

  condition:
    any of them
}