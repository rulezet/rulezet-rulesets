rule TTP_XOR_WriteProcessMemory_b6f2 {
  strings:
    $key_b6f2 = { e1 80 [2] d3 a2 [2] d5 97 [2] fb 97 [2] c4 8b }

  condition:
    any of them
}