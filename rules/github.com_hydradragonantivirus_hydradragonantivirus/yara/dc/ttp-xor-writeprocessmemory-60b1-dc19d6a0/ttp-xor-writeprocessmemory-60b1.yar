rule TTP_XOR_WriteProcessMemory_60b1 {
  strings:
    $key_60b1 = { 37 c3 [2] 05 e1 [2] 03 d4 [2] 2d d4 [2] 12 c8 }

  condition:
    any of them
}