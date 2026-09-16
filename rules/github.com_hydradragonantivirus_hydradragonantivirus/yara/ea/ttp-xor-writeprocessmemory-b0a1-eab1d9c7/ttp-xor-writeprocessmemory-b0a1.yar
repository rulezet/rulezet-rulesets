rule TTP_XOR_WriteProcessMemory_b0a1 {
  strings:
    $key_b0a1 = { e7 d3 [2] d5 f1 [2] d3 c4 [2] fd c4 [2] c2 d8 }

  condition:
    any of them
}