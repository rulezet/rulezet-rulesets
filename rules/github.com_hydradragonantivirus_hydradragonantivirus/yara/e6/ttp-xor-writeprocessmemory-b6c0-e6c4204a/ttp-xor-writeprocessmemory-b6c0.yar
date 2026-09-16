rule TTP_XOR_WriteProcessMemory_b6c0 {
  strings:
    $key_b6c0 = { e1 b2 [2] d3 90 [2] d5 a5 [2] fb a5 [2] c4 b9 }

  condition:
    any of them
}