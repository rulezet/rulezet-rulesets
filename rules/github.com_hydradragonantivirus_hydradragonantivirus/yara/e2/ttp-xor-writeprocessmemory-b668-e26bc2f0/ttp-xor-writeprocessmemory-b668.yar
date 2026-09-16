rule TTP_XOR_WriteProcessMemory_b668 {
  strings:
    $key_b668 = { e1 1a [2] d3 38 [2] d5 0d [2] fb 0d [2] c4 11 }

  condition:
    any of them
}