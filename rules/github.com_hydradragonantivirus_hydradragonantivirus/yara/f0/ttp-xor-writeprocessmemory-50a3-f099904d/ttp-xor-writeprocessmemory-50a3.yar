rule TTP_XOR_WriteProcessMemory_50a3 {
  strings:
    $key_50a3 = { 07 d1 [2] 35 f3 [2] 33 c6 [2] 1d c6 [2] 22 da }

  condition:
    any of them
}