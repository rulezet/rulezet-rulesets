rule TTP_XOR_WriteProcessMemory_71a1 {
  strings:
    $key_71a1 = { 26 d3 [2] 14 f1 [2] 12 c4 [2] 3c c4 [2] 03 d8 }

  condition:
    any of them
}