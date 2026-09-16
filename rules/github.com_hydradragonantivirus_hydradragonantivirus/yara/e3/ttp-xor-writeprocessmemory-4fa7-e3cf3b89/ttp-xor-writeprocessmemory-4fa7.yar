rule TTP_XOR_WriteProcessMemory_4fa7 {
  strings:
    $key_4fa7 = { 18 d5 [2] 2a f7 [2] 2c c2 [2] 02 c2 [2] 3d de }

  condition:
    any of them
}