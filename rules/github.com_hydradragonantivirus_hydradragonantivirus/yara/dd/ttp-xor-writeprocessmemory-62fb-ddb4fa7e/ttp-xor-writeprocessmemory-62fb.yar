rule TTP_XOR_WriteProcessMemory_62fb {
  strings:
    $key_62fb = { 35 89 [2] 07 ab [2] 01 9e [2] 2f 9e [2] 10 82 }

  condition:
    any of them
}