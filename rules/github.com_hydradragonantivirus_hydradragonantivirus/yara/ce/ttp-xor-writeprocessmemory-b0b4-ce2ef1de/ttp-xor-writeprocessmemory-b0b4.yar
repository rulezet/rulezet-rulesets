rule TTP_XOR_WriteProcessMemory_b0b4 {
  strings:
    $key_b0b4 = { e7 c6 [2] d5 e4 [2] d3 d1 [2] fd d1 [2] c2 cd }

  condition:
    any of them
}