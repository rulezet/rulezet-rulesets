rule TTP_XOR_WriteProcessMemory_d3fb {
  strings:
    $key_d3fb = { 84 89 [2] b6 ab [2] b0 9e [2] 9e 9e [2] a1 82 }

  condition:
    any of them
}