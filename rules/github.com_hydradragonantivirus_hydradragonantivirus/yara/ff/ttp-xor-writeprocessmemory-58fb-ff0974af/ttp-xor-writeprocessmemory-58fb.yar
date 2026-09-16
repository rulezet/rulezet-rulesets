rule TTP_XOR_WriteProcessMemory_58fb {
  strings:
    $key_58fb = { 0f 89 [2] 3d ab [2] 3b 9e [2] 15 9e [2] 2a 82 }

  condition:
    any of them
}