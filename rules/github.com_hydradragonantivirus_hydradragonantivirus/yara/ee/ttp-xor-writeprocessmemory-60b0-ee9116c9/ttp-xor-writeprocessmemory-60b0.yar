rule TTP_XOR_WriteProcessMemory_60b0 {
  strings:
    $key_60b0 = { 37 c2 [2] 05 e0 [2] 03 d5 [2] 2d d5 [2] 12 c9 }

  condition:
    any of them
}