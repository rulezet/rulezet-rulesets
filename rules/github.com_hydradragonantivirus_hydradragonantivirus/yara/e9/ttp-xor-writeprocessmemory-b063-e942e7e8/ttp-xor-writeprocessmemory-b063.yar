rule TTP_XOR_WriteProcessMemory_b063 {
  strings:
    $key_b063 = { e7 11 [2] d5 33 [2] d3 06 [2] fd 06 [2] c2 1a }

  condition:
    any of them
}