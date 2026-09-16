rule TTP_XOR_WriteProcessMemory_5fa7 {
  strings:
    $key_5fa7 = { 08 d5 [2] 3a f7 [2] 3c c2 [2] 12 c2 [2] 2d de }

  condition:
    any of them
}