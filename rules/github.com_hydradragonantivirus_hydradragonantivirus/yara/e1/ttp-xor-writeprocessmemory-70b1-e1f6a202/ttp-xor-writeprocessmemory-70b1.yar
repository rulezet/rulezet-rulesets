rule TTP_XOR_WriteProcessMemory_70b1 {
  strings:
    $key_70b1 = { 27 c3 [2] 15 e1 [2] 13 d4 [2] 3d d4 [2] 02 c8 }

  condition:
    any of them
}