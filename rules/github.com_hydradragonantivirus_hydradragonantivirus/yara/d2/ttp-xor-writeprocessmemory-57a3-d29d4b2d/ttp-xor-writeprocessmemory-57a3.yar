rule TTP_XOR_WriteProcessMemory_57a3 {
  strings:
    $key_57a3 = { 00 d1 [2] 32 f3 [2] 34 c6 [2] 1a c6 [2] 25 da }

  condition:
    any of them
}