rule TTP_XOR_WriteProcessMemory_35fb {
  strings:
    $key_35fb = { 62 89 [2] 50 ab [2] 56 9e [2] 78 9e [2] 47 82 }

  condition:
    any of them
}