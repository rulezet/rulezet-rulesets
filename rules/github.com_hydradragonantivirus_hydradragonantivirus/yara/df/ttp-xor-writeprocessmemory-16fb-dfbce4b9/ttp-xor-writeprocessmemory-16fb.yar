rule TTP_XOR_WriteProcessMemory_16fb {
  strings:
    $key_16fb = { 41 89 [2] 73 ab [2] 75 9e [2] 5b 9e [2] 64 82 }

  condition:
    any of them
}