rule TTP_XOR_WriteProcessMemory_b0d0 {
  strings:
    $key_b0d0 = { e7 a2 [2] d5 80 [2] d3 b5 [2] fd b5 [2] c2 a9 }

  condition:
    any of them
}