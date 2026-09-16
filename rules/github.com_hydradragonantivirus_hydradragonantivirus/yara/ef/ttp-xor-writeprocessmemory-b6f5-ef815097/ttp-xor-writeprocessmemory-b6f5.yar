rule TTP_XOR_WriteProcessMemory_b6f5 {
  strings:
    $key_b6f5 = { e1 87 [2] d3 a5 [2] d5 90 [2] fb 90 [2] c4 8c }

  condition:
    any of them
}