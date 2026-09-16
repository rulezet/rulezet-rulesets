rule TTP_XOR_WriteProcessMemory_42fb {
  strings:
    $key_42fb = { 15 89 [2] 27 ab [2] 21 9e [2] 0f 9e [2] 30 82 }

  condition:
    any of them
}