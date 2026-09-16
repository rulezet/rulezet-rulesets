rule TTP_XOR_WriteProcessMemory_60b4 {
  strings:
    $key_60b4 = { 37 c6 [2] 05 e4 [2] 03 d1 [2] 2d d1 [2] 12 cd }

  condition:
    any of them
}