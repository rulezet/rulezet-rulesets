rule TTP_XOR_WriteProcessMemory_b000 {
  strings:
    $key_b000 = { e7 72 [2] d5 50 [2] d3 65 [2] fd 65 [2] c2 79 }

  condition:
    any of them
}