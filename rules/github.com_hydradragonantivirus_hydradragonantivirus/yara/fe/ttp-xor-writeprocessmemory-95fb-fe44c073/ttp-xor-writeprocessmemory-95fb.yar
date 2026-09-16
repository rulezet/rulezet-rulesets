rule TTP_XOR_WriteProcessMemory_95fb {
  strings:
    $key_95fb = { c2 89 [2] f0 ab [2] f6 9e [2] d8 9e [2] e7 82 }

  condition:
    any of them
}