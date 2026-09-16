rule TTP_XOR_WriteProcessMemory_61fb {
  strings:
    $key_61fb = { 36 89 [2] 04 ab [2] 02 9e [2] 2c 9e [2] 13 82 }

  condition:
    any of them
}