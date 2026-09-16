rule TTP_XOR_WriteProcessMemory_b0dd {
  strings:
    $key_b0dd = { e7 af [2] d5 8d [2] d3 b8 [2] fd b8 [2] c2 a4 }

  condition:
    any of them
}