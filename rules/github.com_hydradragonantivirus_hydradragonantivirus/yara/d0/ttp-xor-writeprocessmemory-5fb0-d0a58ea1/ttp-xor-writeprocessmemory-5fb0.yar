rule TTP_XOR_WriteProcessMemory_5fb0 {
  strings:
    $key_5fb0 = { 08 c2 [2] 3a e0 [2] 3c d5 [2] 12 d5 [2] 2d c9 }

  condition:
    any of them
}