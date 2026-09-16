rule TTP_XOR_WriteProcessMemory_22fb {
  strings:
    $key_22fb = { 75 89 [2] 47 ab [2] 41 9e [2] 6f 9e [2] 50 82 }

  condition:
    any of them
}