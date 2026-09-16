rule TTP_XOR_WriteProcessMemory_d6fb {
  strings:
    $key_d6fb = { 81 89 [2] b3 ab [2] b5 9e [2] 9b 9e [2] a4 82 }

  condition:
    any of them
}