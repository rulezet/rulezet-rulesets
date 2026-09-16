rule TTP_XOR_WriteProcessMemory_96fb {
  strings:
    $key_96fb = { c1 89 [2] f3 ab [2] f5 9e [2] db 9e [2] e4 82 }

  condition:
    any of them
}