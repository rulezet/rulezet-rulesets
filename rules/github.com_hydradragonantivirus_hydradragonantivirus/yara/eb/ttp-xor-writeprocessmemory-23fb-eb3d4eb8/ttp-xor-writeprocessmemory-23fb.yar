rule TTP_XOR_WriteProcessMemory_23fb {
  strings:
    $key_23fb = { 74 89 [2] 46 ab [2] 40 9e [2] 6e 9e [2] 51 82 }

  condition:
    any of them
}