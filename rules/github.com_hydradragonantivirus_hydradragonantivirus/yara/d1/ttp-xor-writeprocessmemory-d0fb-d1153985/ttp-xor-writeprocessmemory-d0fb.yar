rule TTP_XOR_WriteProcessMemory_d0fb {
  strings:
    $key_d0fb = { 87 89 [2] b5 ab [2] b3 9e [2] 9d 9e [2] a2 82 }

  condition:
    any of them
}