rule TTP_XOR_WriteProcessMemory_b0f5 {
  strings:
    $key_b0f5 = { e7 87 [2] d5 a5 [2] d3 90 [2] fd 90 [2] c2 8c }

  condition:
    any of them
}