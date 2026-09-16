rule TTP_XOR_WriteProcessMemory_b050 {
  strings:
    $key_b050 = { e7 22 [2] d5 00 [2] d3 35 [2] fd 35 [2] c2 29 }

  condition:
    any of them
}