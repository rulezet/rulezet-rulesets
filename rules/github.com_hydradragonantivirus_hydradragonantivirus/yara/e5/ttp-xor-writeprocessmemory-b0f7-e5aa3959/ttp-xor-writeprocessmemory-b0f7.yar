rule TTP_XOR_WriteProcessMemory_b0f7 {
  strings:
    $key_b0f7 = { e7 85 [2] d5 a7 [2] d3 92 [2] fd 92 [2] c2 8e }

  condition:
    any of them
}