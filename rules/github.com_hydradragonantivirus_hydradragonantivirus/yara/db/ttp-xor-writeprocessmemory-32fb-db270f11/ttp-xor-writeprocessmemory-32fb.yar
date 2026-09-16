rule TTP_XOR_WriteProcessMemory_32fb {
  strings:
    $key_32fb = { 65 89 [2] 57 ab [2] 51 9e [2] 7f 9e [2] 40 82 }

  condition:
    any of them
}