rule TTP_XOR_WriteProcessMemory_b0a4 {
  strings:
    $key_b0a4 = { e7 d6 [2] d5 f4 [2] d3 c1 [2] fd c1 [2] c2 dd }

  condition:
    any of them
}