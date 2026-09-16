rule TTP_XOR_WriteProcessMemory_45fb {
  strings:
    $key_45fb = { 12 89 [2] 20 ab [2] 26 9e [2] 08 9e [2] 37 82 }

  condition:
    any of them
}