rule TTP_XOR_WriteProcessMemory_87fb {
  strings:
    $key_87fb = { d0 89 [2] e2 ab [2] e4 9e [2] ca 9e [2] f5 82 }

  condition:
    any of them
}