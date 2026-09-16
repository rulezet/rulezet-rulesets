rule TTP_XOR_WriteProcessMemory_5fb1 {
  strings:
    $key_5fb1 = { 08 c3 [2] 3a e1 [2] 3c d4 [2] 12 d4 [2] 2d c8 }

  condition:
    any of them
}