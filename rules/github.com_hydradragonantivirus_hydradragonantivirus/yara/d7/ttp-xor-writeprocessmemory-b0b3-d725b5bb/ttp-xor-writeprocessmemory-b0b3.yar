rule TTP_XOR_WriteProcessMemory_b0b3 {
  strings:
    $key_b0b3 = { e7 c1 [2] d5 e3 [2] d3 d6 [2] fd d6 [2] c2 ca }

  condition:
    any of them
}