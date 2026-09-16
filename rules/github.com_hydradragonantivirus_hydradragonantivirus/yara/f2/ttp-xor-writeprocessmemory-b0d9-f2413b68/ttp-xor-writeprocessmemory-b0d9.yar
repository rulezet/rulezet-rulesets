rule TTP_XOR_WriteProcessMemory_b0d9 {
  strings:
    $key_b0d9 = { e7 ab [2] d5 89 [2] d3 bc [2] fd bc [2] c2 a0 }

  condition:
    any of them
}