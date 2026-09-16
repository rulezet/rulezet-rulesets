rule TTP_XOR_WriteProcessMemory_12fb {
  strings:
    $key_12fb = { 45 89 [2] 77 ab [2] 71 9e [2] 5f 9e [2] 60 82 }

  condition:
    any of them
}