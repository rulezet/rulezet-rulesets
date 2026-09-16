rule TTP_XOR_WriteProcessMemory_71b1 {
  strings:
    $key_71b1 = { 26 c3 [2] 14 e1 [2] 12 d4 [2] 3c d4 [2] 03 c8 }

  condition:
    any of them
}