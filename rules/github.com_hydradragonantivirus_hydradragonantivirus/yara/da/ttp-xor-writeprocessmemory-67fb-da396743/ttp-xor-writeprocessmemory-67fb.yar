rule TTP_XOR_WriteProcessMemory_67fb {
  strings:
    $key_67fb = { 30 89 [2] 02 ab [2] 04 9e [2] 2a 9e [2] 15 82 }

  condition:
    any of them
}