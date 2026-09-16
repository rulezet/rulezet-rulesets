rule TTP_XOR_WriteProcessMemory_e4fb {
  strings:
    $key_e4fb = { b3 89 [2] 81 ab [2] 87 9e [2] a9 9e [2] 96 82 }

  condition:
    any of them
}