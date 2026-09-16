rule TTP_XOR_WriteProcessMemory_93fb {
  strings:
    $key_93fb = { c4 89 [2] f6 ab [2] f0 9e [2] de 9e [2] e1 82 }

  condition:
    any of them
}