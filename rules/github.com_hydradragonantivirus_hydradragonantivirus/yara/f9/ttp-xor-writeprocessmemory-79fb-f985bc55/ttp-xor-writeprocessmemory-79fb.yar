rule TTP_XOR_WriteProcessMemory_79fb {
  strings:
    $key_79fb = { 2e 89 [2] 1c ab [2] 1a 9e [2] 34 9e [2] 0b 82 }

  condition:
    any of them
}