rule TTP_XOR_WriteProcessMemory_74fb {
  strings:
    $key_74fb = { 23 89 [2] 11 ab [2] 17 9e [2] 39 9e [2] 06 82 }

  condition:
    any of them
}