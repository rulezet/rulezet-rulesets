rule TTP_XOR_WriteProcessMemory_4fb0 {
  strings:
    $key_4fb0 = { 18 c2 [2] 2a e0 [2] 2c d5 [2] 02 d5 [2] 3d c9 }

  condition:
    any of them
}