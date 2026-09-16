rule TTP_XOR_WriteProcessMemory_c8fb {
  strings:
    $key_c8fb = { 9f 89 [2] ad ab [2] ab 9e [2] 85 9e [2] ba 82 }

  condition:
    any of them
}