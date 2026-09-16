rule TTP_XOR_WriteProcessMemory_71a6 {
  strings:
    $key_71a6 = { 26 d4 [2] 14 f6 [2] 12 c3 [2] 3c c3 [2] 03 df }

  condition:
    any of them
}