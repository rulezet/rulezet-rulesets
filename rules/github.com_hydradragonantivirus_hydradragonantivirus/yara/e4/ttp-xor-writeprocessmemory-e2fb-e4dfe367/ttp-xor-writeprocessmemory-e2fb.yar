rule TTP_XOR_WriteProcessMemory_e2fb {
  strings:
    $key_e2fb = { b5 89 [2] 87 ab [2] 81 9e [2] af 9e [2] 90 82 }

  condition:
    any of them
}