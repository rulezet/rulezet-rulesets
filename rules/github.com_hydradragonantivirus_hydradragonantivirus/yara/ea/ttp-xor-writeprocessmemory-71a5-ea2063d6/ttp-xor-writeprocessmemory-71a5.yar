rule TTP_XOR_WriteProcessMemory_71a5 {
  strings:
    $key_71a5 = { 26 d7 [2] 14 f5 [2] 12 c0 [2] 3c c0 [2] 03 dc }

  condition:
    any of them
}