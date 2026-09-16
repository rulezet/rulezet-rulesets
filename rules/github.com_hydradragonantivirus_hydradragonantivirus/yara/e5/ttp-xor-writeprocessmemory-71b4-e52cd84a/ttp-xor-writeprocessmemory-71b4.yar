rule TTP_XOR_WriteProcessMemory_71b4 {
  strings:
    $key_71b4 = { 26 c6 [2] 14 e4 [2] 12 d1 [2] 3c d1 [2] 03 cd }

  condition:
    any of them
}