rule TTP_XOR_WriteProcessMemory_0fa7 {
  strings:
    $key_0fa7 = { 58 d5 [2] 6a f7 [2] 6c c2 [2] 42 c2 [2] 7d de }

  condition:
    any of them
}