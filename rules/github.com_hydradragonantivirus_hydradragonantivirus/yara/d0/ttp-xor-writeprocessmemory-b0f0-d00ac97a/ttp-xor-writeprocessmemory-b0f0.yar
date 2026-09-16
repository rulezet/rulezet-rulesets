rule TTP_XOR_WriteProcessMemory_b0f0 {
  strings:
    $key_b0f0 = { e7 82 [2] d5 a0 [2] d3 95 [2] fd 95 [2] c2 89 }

  condition:
    any of them
}