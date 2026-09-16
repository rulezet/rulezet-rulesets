rule TTP_XOR_WriteProcessMemory_5eb1 {
  strings:
    $key_5eb1 = { 09 c3 [2] 3b e1 [2] 3d d4 [2] 13 d4 [2] 2c c8 }

  condition:
    any of them
}