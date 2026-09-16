rule TTP_XOR_WriteProcessMemory_71a7 {
  strings:
    $key_71a7 = { 26 d5 [2] 14 f7 [2] 12 c2 [2] 3c c2 [2] 03 de }

  condition:
    any of them
}