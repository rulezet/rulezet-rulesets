rule TTP_XOR_WriteProcessMemory_91fb {
  strings:
    $key_91fb = { c6 89 [2] f4 ab [2] f2 9e [2] dc 9e [2] e3 82 }

  condition:
    any of them
}