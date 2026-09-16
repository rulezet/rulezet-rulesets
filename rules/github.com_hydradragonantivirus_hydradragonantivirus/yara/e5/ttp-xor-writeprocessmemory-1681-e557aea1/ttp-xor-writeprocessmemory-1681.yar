rule TTP_XOR_WriteProcessMemory_1681 {
  strings:
    $key_1681 = { 41 f3 [2] 73 d1 [2] 75 e4 [2] 5b e4 [2] 64 f8 }

  condition:
    any of them
}