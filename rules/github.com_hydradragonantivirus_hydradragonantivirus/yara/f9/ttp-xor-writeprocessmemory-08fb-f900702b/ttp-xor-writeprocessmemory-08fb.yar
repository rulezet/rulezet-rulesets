rule TTP_XOR_WriteProcessMemory_08fb {
  strings:
    $key_08fb = { 5f 89 [2] 6d ab [2] 6b 9e [2] 45 9e [2] 7a 82 }

  condition:
    any of them
}