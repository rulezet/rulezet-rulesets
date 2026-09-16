rule TTP_XOR_WriteProcessMemory_00fb {
  strings:
    $key_00fb = { 57 89 [2] 65 ab [2] 63 9e [2] 4d 9e [2] 72 82 }

  condition:
    any of them
}