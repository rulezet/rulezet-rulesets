rule TTP_XOR_WriteProcessMemory_e1fb {
  strings:
    $key_e1fb = { b6 89 [2] 84 ab [2] 82 9e [2] ac 9e [2] 93 82 }

  condition:
    any of them
}