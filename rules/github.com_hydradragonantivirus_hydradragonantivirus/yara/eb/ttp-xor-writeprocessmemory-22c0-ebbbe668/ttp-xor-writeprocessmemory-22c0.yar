rule TTP_XOR_WriteProcessMemory_22c0 {
  strings:
    $key_22c0 = { 75 b2 [2] 47 90 [2] 41 a5 [2] 6f a5 [2] 50 b9 }

  condition:
    any of them
}