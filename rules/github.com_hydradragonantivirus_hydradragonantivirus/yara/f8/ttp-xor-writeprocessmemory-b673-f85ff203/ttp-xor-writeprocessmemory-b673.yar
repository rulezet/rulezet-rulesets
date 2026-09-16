rule TTP_XOR_WriteProcessMemory_b673 {
  strings:
    $key_b673 = { e1 01 [2] d3 23 [2] d5 16 [2] fb 16 [2] c4 0a }

  condition:
    any of them
}