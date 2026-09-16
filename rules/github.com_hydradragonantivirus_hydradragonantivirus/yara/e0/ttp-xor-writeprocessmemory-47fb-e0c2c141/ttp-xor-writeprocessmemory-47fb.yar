rule TTP_XOR_WriteProcessMemory_47fb {
  strings:
    $key_47fb = { 10 89 [2] 22 ab [2] 24 9e [2] 0a 9e [2] 35 82 }

  condition:
    any of them
}